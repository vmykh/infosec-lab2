package timeprovider

// TODO(vmykh): add logging
import (
	"net"
	"fmt"
	"github.com/vmykh/infosec/lab2/utils"
	//"encoding/gob"
	//"bytes"
	//"github.com/vmykh/infosec/lab2/protocol"
	//"crypto/md5"
	//"time"
	//"encoding/binary"
	//"bytes"
	"github.com/vmykh/infosec/lab2/protocol"
	//"encoding/json"
	"time"
	"crypto/rsa"
	//"crypto/rand"
	//"crypto/sha256"
	//"crypto"
	"github.com/vmykh/infosec/lab2/rsautils"
	"github.com/vmykh/infosec/lab2/keygen"
	//"encoding/base32"
	"strconv"
	"math/rand"
	"errors"
	//"reflect"
)

const Port = 7600

const (
	maxInt64 int64 = (1 << 63) - 1
)

var tsPrivateKey *rsa.PrivateKey;

func StartTimeserver() {
	priv := new(rsa.PrivateKey)
	rsautils.LoadKey(keygen.GetKeyDir() + "/timeserver/timeserver-private.key", priv)
	tsPrivateKey = priv

	service := ":" + strconv.Itoa(Port)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	utils.ExitIfError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.ExitIfError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		fmt.Println("Time server: Client connected!")
		go handleTimeserverClient(conn)
	}

}

func handleTimeserverClient(conn net.Conn) {
	defer conn.Close()

	msg, err := protocol.ReadNetworkMessage(conn)
	if err != nil {
		// TODO(vmykh): maybe panic in such situations (in separate thread)
		fmt.Println(err)
		return
	}
	timeReq, ok := msg.(*protocol.TimeRequest)
	if !ok {
		fmt.Println("Error. Received wrong message: ")
		fmt.Println(msg)
		return
	}

	timestamp := time.Now().Unix();

	signature := protocol.SignTimestamp(timestamp, timeReq.Seed, tsPrivateKey)
	timeRes := protocol.TimeResponse{timestamp, signature}

	timeResBytes, err := protocol.ConstructNetworkMessage(&timeRes)
	if err != nil{
		fmt.Println(err)
		return
	}

	// TODO(vmykh): should we handle error here?
	conn.Write(timeResBytes)
}

func GetTimeFromProvider(tsAddr *net.TCPAddr, tsPub *rsa.PublicKey) (timestamp int64, err error) {
	// connect
	conn, err := net.DialTCP("tcp", nil, tsAddr)
	if err != nil {
		return 0, err
	}

	// create request
	// TODO(vmykh): use secure random instead
	seed := rand.Int63n(maxInt64)
	msgBytes, err := protocol.ConstructNetworkMessage(&protocol.TimeRequest{seed})
	if err != nil {
		return 0, err
	}

	// send request
	n, err := conn.Write(msgBytes)
	if err != nil {
		return 0, err
	}
	if n != len(msgBytes) {
		return 0, errors.New("Some data was not written")
	}


	// handle response
	msg, err := protocol.ReadNetworkMessage(conn)
	if err != nil {
		return 0, err
	}
	timeRes, ok := msg.(*protocol.TimeResponse)
	if !ok {
		return 0, errors.New("Received wrong message")
	}

	// verify timestamp
	err = protocol.VerifyTimestamp(timeRes.Timestamp, seed, timeRes.Signature, tsPub)
	if err != nil {
		return 0, err
	}

	return timeRes.Timestamp, nil
}


