package main

import (
	//"github.com/vmykh/infosec/lab2/utils"
	"net"
	//"crypto/rsa"
	//"github.com/vmykh/infosec/lab2/rsautils"
	//"github.com/vmykh/infosec/lab2/keygen"
	//"github.com/vmykh/infosec/lab2/timeprovider"
	"github.com/vmykh/infosec/lab2/protocol"
	"fmt"
	"crypto/rsa"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/keygen"
	"math/rand"
	"github.com/vmykh/infosec/lab2/utils"
	"log"
	"reflect"
	//"libs/gopass"
	"os"
	"bufio"
	"libs/gopass"
	"strconv"
)

const ClientID = "client_1"

const (
	tsAddr = "localhost:7600"
)

type client struct {
	priv     *rsa.PrivateKey
	tsPub    *rsa.PublicKey
	tsAddr   *net.TCPAddr
	trentPub *rsa.PublicKey
}

// TODO(vmykh): make consistent error handling
func main() {
	clientState := loadClientState()

	trentAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7500")
	if err != nil {
		panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, trentAddr)
	if err != nil {
		panic(err)
	}

	reqBytes, err := protocol.ConstructNetworkMessage(&protocol.TrentRequest{"client_1", "server_1"})
	if err != nil {
		panic(err)
	}

	conn.Write(reqBytes)

	msg, err := protocol.ReadNetworkMessage(conn)
	if err != nil {
		panic(err)
	}

	trentRes, ok := msg.(*protocol.TrentResponse)
	if !ok {
		panic("Cannot convert msg to TrentResponse")
	}

	// TODO(vmykh): add verifying certificates
	fmt.Println(trentRes)

	// TODO(vmykh): close connection with trent


	// connect to server
	serverAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7700")
	if err != nil {
		panic(err)
	}

	servConn, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		panic(err)
	}

	r1 := int32(rand.Int())
	fmt.Printf("rand: %d\n", r1)

	serverPub, err := protocol.ParsePublikKey(trentRes.ServerCert.Pub)
	utils.PanicIfError(err)
	r1Encrypted := protocol.EncryptNumber(r1, serverPub)
	serverReq := protocol.PeersConnectRequest{trentRes.ClientCert, r1Encrypted}
	serverReqBytes, err := protocol.ConstructNetworkMessage(&serverReq)
	utils.PanicIfError(err)

	servConn.Write(serverReqBytes)

	servMsg, err := protocol.ReadNetworkMessage(servConn)
	utils.PanicIfError(err)

	peersConnRes, ok := servMsg.(*protocol.PeersConnectResponse)
	if !ok {
		log.Println("Error. Received wrong type of message: " + reflect.TypeOf(msg).String())
	}

	f1 := protocol.DecryptNumber(peersConnRes.F1, clientState.priv)
	if f1 != (r1 + 1) {
		panic("Error F1 is not correct")
	}

	r2 := protocol.DecryptNumber(peersConnRes.R2, clientState.priv)

	fmt.Printf("Server response F1: %d\n", f1)
	fmt.Printf("Server response R2: %d\n", r2)

	sKey := protocol.CreateSymmetricKey(r1, r2)

	fmt.Printf("Session Key: %d\n", sKey)

	startSession(protocol.NewSecureConn(servConn, sKey))
}

func startSession(conn net.Conn) {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter login: ")
	login , _ := reader.ReadString('\n')
	login = login[:len(login) - 1]

	fmt.Println("Enter password:")
	passBytes, err := gopass.GetPasswdMasked()
	if err != nil {
		os.Exit(1)
	}
	pass := string(passBytes)

	msgBytes, err := protocol.ConstructNetworkMessage(&protocol.LoginRequest{login, pass})
	utils.PanicIfError(err)
	_, err = conn.Write(msgBytes)
	utils.PanicIfError(err)

	msg, err := protocol.ReadNetworkMessage(conn)
	utils.PanicIfError(err)
	fmt.Println("=====")
	fmt.Println(msg)

	for {
		fmt.Println("-----")
		fmt.Println("Available actions:")
		fmt.Println("1 - Change Password")
		fmt.Println("2 - Fetch Document")
		fmt.Println("3 - Add User")
		fmt.Println("4 - Block User")
		fmt.Println("5 - Exit")
		fmt.Print("Your choice: ")
		actionStr , _ := reader.ReadString('\n')
		action, err := strconv.Atoi(actionStr[:len(actionStr) - 1])
		utils.PanicIfError(err)

		switch action {
		case 1:
			fmt.Println("Enter old password:")
			passBytes, err := gopass.GetPasswdMasked()
			if err != nil {
				os.Exit(1)
			}
			oldpass := string(passBytes)

			fmt.Println("Enter new password:")
			passBytes, err = gopass.GetPasswdMasked()
			if err != nil {
				os.Exit(1)
			}
			newpass := string(passBytes)

			msgBytes, err := protocol.ConstructNetworkMessage(&protocol.ChangePasswordRequest{oldpass, newpass})
			utils.PanicIfError(err)
			_, err = conn.Write(msgBytes)
			utils.PanicIfError(err)
		default:
			fmt.Println("Unrecognized command")
			continue
		}

		msg, err := protocol.ReadNetworkMessage(conn)
		utils.PanicIfError(err)
		servRes := msg.(*protocol.ServerResponse)
		fmt.Println("=====")
		fmt.Println(servRes.Message)

	}

	//msgBytes2, err := protocol.ConstructNetworkMessage(&protocol.AddUserRequest{"syrnyk", "kiev"})
	//utils.PanicIfError(err)
	//_, err = conn.Write(msgBytes2)
	//utils.PanicIfError(err)
	//
	//msg, err = protocol.ReadNetworkMessage(conn)
	//utils.PanicIfError(err)
	//fmt.Println("Received: ")
	//fmt.Println(msg)
}

func loadClientState() *client {
	tsTcpAddr, err := net.ResolveTCPAddr("tcp4", tsAddr)
	if err != nil {
		panic(err)
	}
	tsPubKey := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir()+"/client/timeserver-public.key", tsPubKey)

	trentPub := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir()+"/client/trent-public.key", trentPub)

	clientPriv := new(rsa.PrivateKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "/client/client-private.key", clientPriv)

	return &client{clientPriv, tsPubKey, tsTcpAddr, trentPub}
}
