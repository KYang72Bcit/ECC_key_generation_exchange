package main

import (
	"bufio"
	"fmt"
	"net"
)

type ServerState int

const(
	Init ServerState = iota
	KeyGeneration
	EstablishConnection
	KeyExchange
	GenerateSharedSecret
	ReceivedString
	DecodeString
	FatalError
	Termination
)

type ServerFSM struct {
	currentState ServerState
	err error
	ip net.IP
	port int
	conn net.TCPConn 
	writer *bufio.ReadWriter
	privateKey string
	publicKey string
	shareSecret string
	stringReceived string
}


func(fsm *ServerFSM) init_state() ServerState {
	return 1
}

func(fsm *ServerFSM) key_generation_state() ServerState {
	return 1
}

func(fsm *ServerFSM) establish_connection_state() ServerState {
	return 1
}

func(fsm *ServerFSM) key_exchange_state() ServerState {
	return 1
}

func(fsm *ServerFSM) generate_shared_secret_state() ServerState {
	return 1
}

func(fsm *ServerFSM) receive_string_state() ServerState {
	return 1
}

func(fsm *ServerFSM) decode_state() ServerState {
	return 1
}

func(fsm *ServerFSM) fatal_error_state() ServerState {
	return 1
}

func(fsm *ServerFSM) termination_state() ServerState {
	return 1
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
			case DecodeString:
				fsm.currentState = fsm.decode_state()
			case FatalError:
				fsm.currentState = fsm.fatal_error_state()
			case Termination:
				fsm.termination_state()
				return
		}
	}
}

