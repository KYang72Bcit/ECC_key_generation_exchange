package main

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -lcrypto -L. -lcry
#include "key.h"
*/

import (
	"C"
	"bufio"
	"flag"
	"fmt"
	"net"
)
import (
	"errors"
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

// 	fmt.Println("Key created %s, %s :", C.GoString(pubKeyStr), C.GoString(privKeyStr))
// }

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

type ClientFSM struct {
	currentState ClientState
	err error
	ip net.IP
	port int
	conn net.TCPConn
	writer *bufio.ReadWriter
	privateKey string
	publicKey string
	shareSecret string
	message string
}

func NewClientFSM() *ClientFSM {
	return &ClientFSM{
		currentState: Init,
	}
}

func(fsm *ClientFSM) init_state() ClientState {
	var ip, port string;
	flag.StringVar(&ip, "ip", "", "enter IP")
	flag.StringVar(&port, "port", "6666", "enter port")
	flag.StringVar(&fsm.message, "message", "", "enter message")
	flag.Parse()
	fsm.ip, fsm.err = validateIP(ip)
	if fsm.err != nil {
		return FatalError
	}

	fsm.port, fsm.err = validatePort(port)
	if fsm.err != nil {
		return FatalError
	}

	if fsm.message == "" {
		fsm.err = errors.New("No message to encrypt")
	}


	return KeyGeneration
}

func(fsm *ClientFSM) key_generation_state() ClientState {
	key := C.create_key()
	if key == nil {
		fmt.Println("Failed to create key")
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
	return Termination
}

func(fsm *ClientFSM) establish_connection_state() ClientState {
	return 1
}

func(fsm *ClientFSM) key_exchange_state() ClientState {
	return 1
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
	// if fsm.conn != nil {
	// 	fsm.conn.Close()
	// }


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
