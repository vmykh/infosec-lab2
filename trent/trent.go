package trent

import (
	"net"
	"fmt"
	"github.com/vmykh/infosec/lab2/utils"
	//"encoding/gob"
	//"bytes"
	"github.com/vmykh/infosec/lab2/protocol"
	"crypto/rsa"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/keygen"
	"github.com/vmykh/infosec/lab2/timeprovider"
)

const (
	tsAddr = "localhost:7600"
)

type trent struct {
	hostIdToKey map[string]*rsa.PublicKey
	tsTcpAddr   *net.TCPAddr
	tsPubKey    *rsa.PublicKey
	privKey     *rsa.PrivateKey
}

func StartTrent() {
	trent := loadTrentState()

	service := ":7500"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	utils.ExitIfError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.ExitIfError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		fmt.Println("Client connected!")
		go handleClient(conn, trent)
	}
}

func loadTrentState() *trent {
	hostIdToKey := loadPubKeys()
	tsTcpAddr, err := net.ResolveTCPAddr("tcp4", tsAddr)
	if err != nil {
		panic(err)
	}
	tsPubKey := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "/trent/timeserver-public.key", tsPubKey)

	trentPriv := new(rsa.PrivateKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "/trent/trent-private.key", trentPriv)

	return &trent{hostIdToKey, tsTcpAddr, tsPubKey, trentPriv}
}

func loadPubKeys() map[string]*rsa.PublicKey {
	keysDir := keygen.GetKeyDir() + "/trent"

	clientPub := new(rsa.PublicKey)
	rsautils.LoadKey(keysDir + "/client-public.key", clientPub)

	serverPub := new(rsa.PublicKey)
	rsautils.LoadKey(keysDir + "/server-public.key", serverPub)

	idToKey := make(map[string]*rsa.PublicKey)
	idToKey["client_1"] = clientPub
	idToKey["server_1"] = serverPub
	return idToKey
}

func handleClient(conn net.Conn, trentState *trent) {
	defer conn.Close()

	// read request
	msg, err := protocol.ReadNetworkMessage(conn)
	if err != nil {
		fmt.Println(err)
		return
	}
	trentReq, ok := msg.(*protocol.TrentRequest)
	if !ok {
		fmt.Printf("Received wrong type of request: %s\n", trentReq)
		return
	}

	// fetch public keys for hosts
	clientPubKey, ok := trentState.hostIdToKey[trentReq.ClientID]
	if !ok {
		fmt.Printf("Trent doesn't have certivicate for host with id: " + trentReq.ClientID)
		return
	}
	serverPubKey, ok := trentState.hostIdToKey[trentReq.ServerID]
	if !ok {
		fmt.Printf("Trent doesn't have certivicate for host with id: " + trentReq.ServerID)
		return
	}

	// fetch timestamp from time provider
	timestamp, err := timeprovider.GetTimeFromProvider(trentState.tsTcpAddr, trentState.tsPubKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	clientCert, err := protocol.CreateCertificate(trentReq.ClientID, clientPubKey, timestamp, trentState.privKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	serverCert, err := protocol.CreateCertificate(trentReq.ServerID, serverPubKey, timestamp, trentState.privKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	msgBytes, err := protocol.ConstructNetworkMessage(&protocol.TrentResponse{*clientCert, *serverCert})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("-----------")
	fmt.Println("Bytes:")
	fmt.Println(string(msgBytes))
	conn.Write(msgBytes)
}
