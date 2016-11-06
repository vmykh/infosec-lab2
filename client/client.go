package main

import (
	"github.com/vmykh/infosec/lab2/utils"
	"net"
	"crypto/rsa"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/keygen"
	"github.com/vmykh/infosec/lab2/timeprovider"
)

const ClientID = "default_client"

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

	GetTimeFromServer()
}



func GetTimeFromServer() (timestamp int64, err error) {
	pub := new(rsa.PublicKey)
	rsautils.LoadKey(keygen.KeyDir + "client/timeserver-public.key", pub)

	serverAddr, err := net.ResolveTCPAddr("tcp4", "localhost:7600")
	utils.ExitIfError(err)

	timeprovider.GetTimeFromProvider(serverAddr, pub)

	return 0, nil
}
