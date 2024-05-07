package main

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -lcrypto -L. -lcry
#include "key.h"
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"unsafe"
)

type ClientState int

const(
	Init ClientState = iota
	KeyGeneration
	EstablishConnection
	SendMessage
	KeyExchange
	GenerateSharedSecret
	GetUserInput
	Encryption
	SendString
	FatalError
	Termination
)

type ClientFSM struct {
	currentState ClientState
	err error
	ip net.IP
	port int
	conn net.Conn
	key *C.EC_KEY
	privateKey string
	publicKey string
	peerKey *C.EC_POINT
	shareSecret string
	message *string
}

func NewClientFSM() *ClientFSM {
	return &ClientFSM{
		currentState: Init,
	}
}

func(fsm *ClientFSM) init_state() ClientState {

	ip := flag.String("ip", "", "enter IP")
	port := flag.String("port", "", "enter port")
	msg := flag.String("message", "", "enter message")
	flag.Parse()
	fmt.Printf("ip %s\n", *ip)
	fmt.Printf("port %s\n", *port)
	fmt.Printf("message %s\n", *msg)
	fsm.ip, fsm.err = validateIP(*ip)
	if fsm.err != nil {
		return FatalError
	}

	fsm.port, fsm.err = validatePort(*port)
	if fsm.err != nil {
		return FatalError
	}

	if *msg == "" {
		fsm.err = errors.New("No message to encrypt")
		return FatalError
	}

	fsm.message = msg

	return KeyGeneration
}

func(fsm *ClientFSM) key_generation_state() ClientState {
	key := C.create_key()
	if key == nil {
		fsm.err = errors.New("fail to generate key")
		return FatalError
	}
	fsm.key = key
	pubKeyStr := C.get_public_key_str(key)
	privKeyStr := C.get_private_key_str(key)
	defer C.free_string(pubKeyStr)
	defer C.free_string(privKeyStr)
	fsm.publicKey = C.GoString(pubKeyStr)
	fsm.privateKey = C.GoString(privKeyStr)
	fmt.Println("public key", fsm.publicKey)
	fmt.Println("private key", fsm.privateKey)
	return EstablishConnection
}

func(fsm *ClientFSM) establish_connection_state() ClientState {

	addr := fmt.Sprintf("%s:%d", fsm.ip.String(), fsm.port)
	fsm.conn, fsm.err = net.Dial("tcp", addr)
	if fsm.err != nil {
		return FatalError
	}
	return SendMessage
}

func(fsm *ClientFSM) sent_message_state() ClientState {
	_, fsm.err = fsm.conn.Write([]byte(*fsm.message))
	if fsm.err != nil {
		return FatalError
	}
	return KeyExchange

}


func(fsm *ClientFSM) key_exchange_state() ClientState {
	var wg sync.WaitGroup
	wg.Add(2)
	go sendKey(&wg, fsm.conn, fsm.key, fsm.err)
	go receiveKey(&wg, fsm.conn, fsm.peerKey, fsm.err)
	wg.Wait()
	if fsm.err != nil {
		return FatalError
	}
	return GenerateSharedSecret
}


func(fsm *ClientFSM) generate_shared_secret_state() ClientState {
	return 1
}

func(fsm *ClientFSM) get_user_input() ClientState {
	return 1
}

func(fsm *ClientFSM) encryption_state() ClientState {
	return 1
}

func(fsm *ClientFSM) fatal_error_state() ClientState {
	fmt.Println("Fatal Error:", fsm.err)
	return Termination
}

func(fsm *ClientFSM) termination_state() {
	if fsm.conn != nil {
		fsm.conn.Close()
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

//goroutine should not have a return value 
func sendKey(wg *sync.WaitGroup, conn net.Conn,key *C.EC_KEY, er error) {
	defer wg.Done()
	keyToSend, x, y := getPublicKey(key)
	xLength := int32(x)
	yLength := int32(y)
	keyLength := xLength + yLength
	bytes := make([]byte, 4)
	//send x
	binary.BigEndian.PutUint32(bytes, uint32(xLength))

	if _, err := conn.Write(bytes); err != nil {
		er = err
		return 
	}

	//send y
	binary.BigEndian.PutUint32(bytes, uint32(yLength))
	if _, err := conn.Write(bytes); err != nil {
		er = err
		return 
	}

	//send key length
	binary.BigEndian.PutUint32(bytes, uint32(keyLength))
	if _, err := conn.Write(bytes); err != nil {
		er = err
		return 
	}

	if _, err := conn.Write(keyToSend); err != nil {
		er = err
		return 
	}
}

// goroutine should not have a return value 
func receiveKey(wg *sync.WaitGroup, conn net.Conn, peerKey *C.EC_POINT, er error) {
	defer wg.Done()
	//get x length 
	bytes := make([]byte, 4)
    if _, err := io.ReadFull(conn, bytes); err != nil {
        er = err
		return
    }
    x := binary.BigEndian.Uint32(bytes)

	//get y length
    if _, err := io.ReadFull(conn, bytes); err != nil {
        er = err
		return
    }
    y := binary.BigEndian.Uint32(bytes)

    // get key 
    key := make([]byte, x + y)
    if _, err := io.ReadFull(conn, key); err != nil {
        er = err
		return
    }
	xCor := key[:x]
	yCor := key[x:]

	peerKey = bytesToECPoint(xCor, yCor)
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

func main() {
	clientFSM := NewClientFSM()
	clientFSM.Run()
}
