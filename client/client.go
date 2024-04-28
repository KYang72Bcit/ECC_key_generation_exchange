package main

import (
	"bufio"
	"fmt"
	"net"
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
	inputString string
}

func(fsm *ClientFSM) init_state() ClientState {
	return 1
}

func(fsm *ClientFSM) key_generation_state() ClientState {
	return 1
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
	return 1
}

func(fsm *ClientFSM) termination_state() ClientState {
	return 1
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