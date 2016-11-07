package main

import (
	"github.com/vmykh/infosec/lab2/utils"
	"net"
	"crypto/rsa"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/keygen"
	"github.com/vmykh/infosec/lab2/timeprovider"
	"github.com/vmykh/infosec/lab2/protocol"
	"fmt"
)

const ClientID = "default_client"

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

	serverAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7500")
	if err != nil {
		panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, serverAddr)
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

	fmt.Println(trentRes)

}



func GetTimeFromServer() (timestamp int64, err error) {
	pub := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "client/timeserver-public.key", pub)

	serverAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7600")
	utils.ExitIfError(err)

	timeprovider.GetTimeFromProvider(serverAddr, pub)

	return 0, nil
}
