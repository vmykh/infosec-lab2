package trent

import (
	"net"
	"fmt"
	"github.com/vmykh/infosec/lab2/utils"
	"encoding/gob"
	"bytes"
	"github.com/vmykh/infosec/lab2/protocol"
)

func StartTrent() {
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
		go handleClient(conn)
	}

}

func handleClient(conn net.Conn) {
	var b []byte = make([]byte, 1000)
	numRead, err := conn.Read(b)
	decoder := gob.NewDecoder(bytes.NewReader(b[:numRead]))
	var reqDecoded protocol.TrentRequest
	decoder.Decode(&reqDecoded)
	utils.ExitIfError(err)
	//fmt.Printf("received: %s", b[:numRead])
	fmt.Printf("received: %s", reqDecoded)
}
