package main

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -lcrypto -L. -lcry
#include "key.h"
#include <openssl/crypto.h>
*/
import "C"
import (
	"bufio"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

type ClientState int

const(
	Init ClientState = iota
	KeyGeneration
	EstablishConnection
	KeyExchange
	GenerateSharedSecret
	GetUserInput
	Encryption
	SendString
	FatalError
	Termination
)

const bufferSize = 32

type ClientFSM struct {
	currentState ClientState
	err error
	ip net.IP
	port int
	conn net.Conn
	key *C.EC_KEY
	peerPubKey *C.EC_POINT
	sharedSecret []byte
	message string
	ciphertext []byte
	writer *bufio.Writer
	reader *bufio.Reader
} 

func NewClientFSM() *ClientFSM {
	return &ClientFSM{
		currentState: Init,
	}
}

func(fsm *ClientFSM) init_state() ClientState {

	ip := flag.String("ip", "", "enter IP")
	port := flag.String("port", "", "enter port")

	flag.Parse()
	fmt.Printf("ip %s\n", *ip)
	fmt.Printf("port %s\n", *port)

	fsm.ip, fsm.err = validateIP(*ip)
	if fsm.err != nil {
		return FatalError
	}

	fsm.port, fsm.err = validatePort(*port)
	if fsm.err != nil {
		return FatalError
	}

	fmt.Println("init state")
	return KeyGeneration
}

func(fsm *ClientFSM) key_generation_state() ClientState {
	key := C.create_key()
	if key == nil {
		fsm.err = errors.New("fail to generate key")
		return FatalError
	}
	fsm.key = key
	fmt.Println("key generation state")
	return EstablishConnection
}

func(fsm *ClientFSM) establish_connection_state() ClientState {

	addr := fmt.Sprintf("%s:%d", fsm.ip.String(), fsm.port)
	fsm.conn, fsm.err = net.Dial("tcp", addr)
	if fsm.err != nil {
		return FatalError
	}
	fmt.Println("establish connection state")
	fsm.writer = bufio.NewWriter(fsm.conn)
	fsm.reader = bufio.NewReader(fsm.conn)
	return KeyExchange
}


func(fsm *ClientFSM) key_exchange_state() ClientState {
	var wg sync.WaitGroup
	wg.Add(2)
	go sendKey(&wg, fsm.key, fsm.err, fsm.writer)
	go receiveKey(&wg, fsm.reader, &fsm.peerPubKey, fsm.err)
	wg.Wait()
	if fsm.err != nil {
		return FatalError
	}

	if fsm.peerPubKey == nil {
		fsm.err = errors.New("Can not generate peer public key")
		return FatalError	
	}
	
	fmt.Println("key exchange state")
	return GenerateSharedSecret
}


func(fsm *ClientFSM) generate_shared_secret_state() ClientState {
	secret, err := getSharedSecret(fsm.key, fsm.peerPubKey)
	if err != nil {
		fsm.err = err
		return FatalError
	}
	converter := sha256.New()

	_, er := converter.Write(secret)
	if er != nil {
		fsm.err = er
		return FatalError
	}
	
	fsm.sharedSecret = converter.Sum(nil)
	encodedString := base64.StdEncoding.EncodeToString(fsm.sharedSecret)
    fmt.Println("Shared Secret:", encodedString)

	return GetUserInput
}

func(fsm *ClientFSM) get_user_input() ClientState {
	reader := bufio.NewReader(os.Stdin)
    
	for {
		fmt.Print("Enter input (longer than 32 bytes will be trimmed): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Failed to read input:", err)
			continue
		} 
		input = strings.TrimSuffix(input, "\n")
		if len(input) > 32 {
			fsm.message = input[:32]
			fmt.Println("Plain text: ", string(input))
			break
		} else {
			for len(input) < 32 {
				input += "\x00"
			}
			fsm.message = input
			fmt.Println("Plain text: ", string(input))
			break
		}
	}
	return Encryption
    
}

func(fsm *ClientFSM) encryption_state() ClientState {
	block, err := aes.NewCipher(fsm.sharedSecret)
	if err != nil {
		fsm.err = err
		return FatalError
	}

	var ciphertext[]byte
	plaintext := []byte(fsm.message)
	for start := 0; start < len(plaintext); start += aes.BlockSize {
		chunk := make([]byte, aes.BlockSize)
		block.Encrypt(chunk, plaintext[start:start+aes.BlockSize])
		ciphertext = append(ciphertext, chunk...)
	}
	fmt.Println("Ciphertext: ", base64.StdEncoding.EncodeToString(ciphertext))
	return SendString
}

func(fsm *ClientFSM) sent_message_state() ClientState {
	_, fsm.err = sendBytes(fsm.writer, fsm.ciphertext)
	if fsm.err != nil {
		return FatalError
	}
	return Termination

}

func(fsm *ClientFSM) fatal_error_state() ClientState {
	fmt.Println("Fatal Error:", fsm.err)
	return Termination
}

func(fsm *ClientFSM) termination_state() {
	if fsm.conn != nil {
		fsm.conn.Close()
	}

	if fsm.key != nil {
		C.EC_KEY_free(fsm.key)
		
	}

	fmt.Println("client exiting...")

}

func (fsm *ClientFSM) Run() {
	for {
		switch fsm.currentState {
			case Init:
				fsm.currentState = fsm.init_state()
			case KeyGeneration:
				fsm.currentState = fsm.key_generation_state()
			case EstablishConnection:
				fsm.currentState = fsm.establish_connection_state()
			case KeyExchange:
				fsm.currentState = fsm.key_exchange_state()
			case GenerateSharedSecret:
				fsm.currentState = fsm.generate_shared_secret_state()
			case GetUserInput:
				fsm.currentState = fsm.get_user_input()
			case Encryption:
				fsm.currentState = fsm.encryption_state()
			case FatalError:
				fsm.currentState = fsm.fatal_error_state()
			case Termination:
				fsm.termination_state()
				return
		}
	}
}

func validateIP(ip string) (net.IP, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return nil, errors.New("invalid ip address")
	}
	return addr, nil
}

func validatePort(port string) (int, error) {
	portNo, err := strconv.Atoi(port)
	if err != nil || portNo <= 0 || portNo > 65535 {
		return -1, errors.New("invalid port number")
	}
	return portNo, nil
}

func sendKey(wg *sync.WaitGroup, key *C.EC_KEY, err error, writer *bufio.Writer) {
	defer wg.Done()
	keyToSend, x, y := getPublicKey(key)
	fmt.Println("key send", base64.StdEncoding.EncodeToString(keyToSend))
	err = sendInt(writer, x)
	err = sendInt(writer, y)
	_, err = sendBytes(writer, keyToSend)
}

func receiveKey(wg *sync.WaitGroup, reader *bufio.Reader, peerPubKey **C.EC_POINT, err error) {
	defer wg.Done()
	x, err := receiveInt(reader)
	y, err := receiveInt(reader)
	key, err := receiveBytes(reader)
	fmt.Println("key received", base64.StdEncoding.EncodeToString(key))

	fmt.Println("receive X: ", x)
	fmt.Println("receive y: ", y)
	xCor := key[:x]
	yCor := key[x:]

	*peerPubKey = bytesToECPoint(xCor, yCor)
	if peerPubKey == nil {
		fmt.Printf("peer pucblic key is null")
	} else {

		fmt.Printf("peer pucblic key is NOT null")
	}

	
	
}

func getPublicKey(key *C.EC_KEY) ([]byte, int, int) {
	var x, y C.int
	point := C.get_public_key(key, &x, &y)
	defer C.free(unsafe.Pointer(point))

	length := int(x + y)
	keyBytes := C.GoBytes(unsafe.Pointer(point), C.int(length))
	return keyBytes, int(x), int(y)
}

func bytesToECPoint(xCor, yCor []byte) *C.EC_POINT {
	x := C.CBytes(xCor)
	y := C.CBytes(yCor)
	defer C.free(unsafe.Pointer(x))
	defer C.free(unsafe.Pointer(y))
	return C.bytesToECPoint((*C.uchar)(x), C.int(len(xCor)), (*C.uchar)(y), C.int(len(yCor)))
}

func getSharedSecret(key *C.EC_KEY, peerPubKey *C.EC_POINT) ([]byte, error) {
	var secretLen C.size_t

	secret := C.get_secret(key, peerPubKey, &secretLen)
	if secret == nil {
		return nil, errors.New("failed to generate shared secret")
	}
	defer C.free(unsafe.Pointer(secret))

	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLen)), nil
}

func main() {
	clientFSM := NewClientFSM()
	clientFSM.Run()

}

func receiveBytes(reader *bufio.Reader) ([]byte, error) {
	size, err := receiveInt(reader)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	received := 0

	for received < size {
		remaining := size - received
		readSize := bufferSize
		if remaining < readSize {
			readSize = remaining
		}

		n, err := reader.Read(data[received : received+readSize])
		if err != nil {
			return nil, err
		}

		received += n
	}

	return data, nil
}


func receiveInt(reader *bufio.Reader) (int, error) {
	receivedByte := make([]byte, 4)
	_, err := reader.Read(receivedByte)
	if err != nil {
		return -1, err
	}
	receiveInt := binary.BigEndian.Uint32(receivedByte)

	return int(receiveInt), nil
}

func sendInt(writer *bufio.Writer, num int) (error) {
	intSend := int32(num)
	sendBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sendBytes, uint32(intSend))
	_, err := writer.Write(sendBytes)
	if err != nil {
		return err
	}
	return writer.Flush()
}

// sendBytes sends the provided byte array to the provided writer
// It returns an int of the number of data it send, and error if the writer cannot be written to
// error will be nil if there's no error
func sendBytes(writer *bufio.Writer, data []byte) (int, error) {
	err := sendInt(writer, len(data))
	if err != nil {
		return -1, err
	}

	for start := 0; start < len(data); start += bufferSize {
		end := start + bufferSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[start:end]
		_, err := writer.Write(chunk)
		if err != nil {
			return -1, err
		}
		err = writer.Flush()
		if err != nil {
			return -1, err
		}
	}
	return len(data), nil
}