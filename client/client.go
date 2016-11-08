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
	//fmt.Println("Enter password:")
	//pass, err := gopass.GetPasswdMasked()
	//if err != nil {
	//	os.Exit(1)
	//}
	//fmt.Printf("success: %s", pass)

	//serverAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7500")
	//utils.ExitIfError(err)
	//conn, err := net.DialTCP("tcp", nil, serverAddr)
	//utils.ExitIfError(err)
	//
	//var inputNetwork bytes.Buffer
	//enc := gob.NewEncoder(&inputNetwork)
	//
	//enc.Encode(protocol.TrentRequest{"client-foo", "server-bar"})
	//
	////conn.Write([]byte("i'm not a gatussso, SOOOOQAAA!!!!"))
	//conn.Write(inputNetwork.Bytes())
	//
	//time.Now()

	//GetTimeFromServer()

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
	conn.Write([]byte{50, 55, 60})
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
