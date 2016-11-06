package server

import (
	"net"
	"fmt"
	"github.com/vmykh/infosec/lab2/utils"
)

const ServerId = "default_server"

func StartServer() {
	service := ":7700"
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
	var b []byte = make([]byte, 100)
	numRead, err := conn.Read(b)
	utils.ExitIfError(err)
	fmt.Printf("received: %s", b[:numRead])
}

