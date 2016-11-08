package server

import (
	"crypto/rsa"
	"fmt"
	"github.com/vmykh/infosec/lab2/keygen"
	"github.com/vmykh/infosec/lab2/protocol"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/utils"
	"log"
	"net"
	"reflect"
	"math/rand"
)

const ServerId = "server_1"

const (
	tsAddr = "localhost:7600"
)

// TODO(vmykh): rename this type
type server struct {
	priv     *rsa.PrivateKey
	tsPub    *rsa.PublicKey
	tsAddr   *net.TCPAddr
	trentPub *rsa.PublicKey
}

func StartServer() {
	servState := loadServerState()

	service := ":7700"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	utils.PanicIfError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.PanicIfError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		fmt.Println("Client connected to server!")
		go handleClient(conn, servState)
	}

}

func loadServerState() *server {
	tsTcpAddr, err := net.ResolveTCPAddr("tcp4", tsAddr)
	if err != nil {
		panic(err)
	}
	tsPubKey := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir()+"/server/timeserver-public.key", tsPubKey)

	trentPub := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir()+"/server/trent-public.key", trentPub)

	serverPriv := new(rsa.PrivateKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "/server/server-private.key", serverPriv)

	return &server{serverPriv, tsPubKey, tsTcpAddr, trentPub}
}

func handleClient(conn net.Conn, serverState *server) {
	defer conn.Close()

	msg, err := protocol.ReadNetworkMessage(conn)
	utils.PanicIfError(err)

	peersConnReq, ok := msg.(*protocol.PeersConnectRequest)
	if !ok {
		log.Println("Error. Received wrong type of message: " + reflect.TypeOf(msg).String())
	}

	clientCert := &peersConnReq.ClientCert

	// TODO(vmykh): maybe make function like fetchPubKey that will also do verification ?
	err = protocol.VerifyCertificate(clientCert, serverState.trentPub)
	utils.PanicIfError(err)

	clientPub, err := protocol.ParsePublikKey(clientCert.Pub)
	utils.PanicIfError(err)

	r1 := protocol.DecryptNumber(peersConnReq.R1, serverState.priv)
	fmt.Printf("r1 = %d", r1)

	f1 := r1 + 1
	f1Encrypted := protocol.EncryptNumber(f1, clientPub)

	r2 := int32(rand.Int())

	sKey := protocol.CreateSymmetricKey(r1, r2)

	r2Encrypted := protocol.EncryptNumber(r2, clientPub)

	resBytes, err := protocol.ConstructNetworkMessage(&protocol.PeersConnectResponse{f1Encrypted, r2Encrypted})
	utils.PanicIfError(err)

	n, err := conn.Write(resBytes)
	utils.PanicIfError(err)
	if n != len(resBytes) {
		panic("not written fully")
	}

	startSession(protocol.NewSecureConn(conn, sKey))
}
func startSession(conn net.Conn) {
	b, err := utils.ReadExactly(3, conn)
	utils.PanicIfError(err)

	fmt.Println("Received and Decrypted:")
	fmt.Println(b)
}

// region business logic
type model interface {

}

type userHandler interface {

	login(login string, password string)

	addUser(uname string, upass string)

	blockUser(uname string)

	changePassword(uname string, oldpass string, newpass string)

	fetchDocument(name string)
}


// endregion
