package main

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -lcrypto -L. -lcry
#include "key.h"
*/
import "C"
import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
)

// func main() {
// 	key := C.create_key()
// 	if key == nil {
// 		fmt.Println("Failed to create key")
// 		return
// 	}
// 	defer C.EC_KEY_free(key)

// 	pubKeyStr := C.get_public_key(key)
// 	privKeyStr := C.get_private_key(key)
// 	defer C.free_string(pubKeyStr)
// 	defer C.free_string(privKeyStr)

// 	fmt.Println("Key created: ", C.GoString(pubKeyStr), C.GoString(privKeyStr))
// }

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
	writer *bufio.ReadWriter
	privateKey string
	publicKey string
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
	defer C.EC_KEY_free(key)

	pubKeyStr := C.get_public_key(key)
	privKeyStr := C.get_private_key(key)
	defer C.free_string(pubKeyStr)
	defer C.free_string(privKeyStr)
	fsm.publicKey = C.GoString(pubKeyStr)
	fsm.privateKey = C.GoString(privKeyStr)
	fmt.Println("public key", pubKeyStr)
	fmt.Println("public key", privKeyStr)
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

	fmt.Println("UDP server exiting...")

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


func main() {
	clientFSM := NewClientFSM()
	clientFSM.Run()
}
