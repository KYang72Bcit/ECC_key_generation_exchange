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
	"strconv"
	"sync"
	"unsafe"
)

type ServerState int

const(
	Init ServerState = iota
	KeyGeneration
	EstablishConnection
	KeyExchange
	GenerateSharedSecret
	ReceivedString
	Dencryption
	FatalError
	Termination
)
const bufferSize = 32

type ServerFSM struct {
	currentState ServerState
	err error
	ip net.IP
	port int
	listener net.Listener
	conn net.Conn
	key *C.EC_KEY
	peerPubKey *C.EC_POINT
	sharedSecret []byte
	message string
	ciphertext []byte
	writer *bufio.Writer
	reader *bufio.Reader
}

func NewServerFSM() *ServerFSM {
	return &ServerFSM{
		currentState: Init,
	}
}

func(fsm *ServerFSM) init_state() ServerState {
	ip := flag.String("ip", "", "enter IP")
	port := flag.String("port", "", "enter port")

	flag.Parse()
	fsm.ip, fsm.err = validateIP(*ip)

	if fsm.err != nil {
		return FatalError
	}

	fsm.port, fsm.err = validatePort(*port)
	if fsm.err != nil {
		return FatalError
	}

	return KeyGeneration
}

func(fsm *ServerFSM) key_generation_state() ServerState {
	key := C.create_key()
	if key == nil {
		fsm.err = errors.New("fail to generate key")
		return FatalError
	}
	fsm.key = key
	return EstablishConnection
}

func(fsm *ServerFSM) establish_connection_state() ServerState {
	addr := fmt.Sprintf("%s:%d", fsm.ip.String(), fsm.port)
	fsm.listener, fsm.err = net.Listen("tcp", addr)
	if fsm.err != nil {
		return FatalError
	}
	fmt.Println("server listening on port:", fsm.port)
	fsm.conn, fsm.err = fsm.listener.Accept()
	if fsm.err != nil {
		return FatalError
	}
	fsm.writer = bufio.NewWriter(fsm.conn)
	fsm.reader = bufio.NewReader(fsm.conn)
	return KeyExchange
}

func(fsm *ServerFSM) key_exchange_state() ServerState {
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

func(fsm *ServerFSM) generate_shared_secret_state() ServerState {
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
	return ReceivedString
}

func(fsm *ServerFSM) receive_string_state() ServerState {
	fsm.ciphertext, fsm.err = receiveBytes(fsm.reader)

	if (fsm.err != nil ) {
		return FatalError
	}
	fmt.Println("Received Ciphertext: ", base64.StdEncoding.EncodeToString(fsm.ciphertext))
	return Dencryption
}

func(fsm *ServerFSM) decode_state() ServerState {

	block, _ := aes.NewCipher(fsm.sharedSecret)


	var decryptedText []byte
	for start := 0; start < len(fsm.ciphertext); start += aes.BlockSize {
		chunk := make([]byte, aes.BlockSize)
		block.Decrypt(chunk, fsm.ciphertext[start:start+aes.BlockSize])
		decryptedText = append(decryptedText, chunk...)
	}
	fmt.Printf("Decrypted text: %s\n", string(decryptedText))
	return Termination
}

func(fsm *ServerFSM) fatal_error_state() ServerState {
	fmt.Println("Fatal Error:", fsm.err)
	return Termination
}

func(fsm *ServerFSM) termination_state() {
	if fsm.listener != nil {
		fsm.listener.Close()
	}

	if fsm.key != nil {
		C.EC_KEY_free(fsm.key)
	}

	fmt.Println("server exiting...")
}



func (fsm *ServerFSM) Run() {
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
			case ReceivedString:
				fsm.currentState = fsm.receive_string_state()
			case Dencryption:
				fsm.currentState = fsm.decode_state()
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
	fmt.Println("public key send", base64.StdEncoding.EncodeToString(keyToSend))
	err = sendInt(writer, x)
	err = sendInt(writer, y)
	_, err = sendBytes(writer, keyToSend)

}

func receiveKey(wg *sync.WaitGroup, reader *bufio.Reader, peerPubKey **C.EC_POINT, err error) {
	defer wg.Done()
	x, err := receiveInt(reader)
	y, err := receiveInt(reader)
	key, err := receiveBytes(reader)
	fmt.Println("public key received", base64.StdEncoding.EncodeToString(key))

	xCor := key[:x]
	yCor := key[x: x + y]

	*peerPubKey = bytesToECPoint(xCor, yCor)

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
	return C.bytes_to_ECPoint((*C.uchar)(x), C.int(len(xCor)), (*C.uchar)(y), C.int(len(yCor)))
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
	serverFSM := NewServerFSM()
	serverFSM.Run()
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
