package server

// TODO(vmykh): separate server connection handling logic and user management into  different modules

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
	"errors"
	"io/ioutil"
	"os"
	"time"
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
	usrManager userManager
}

func StartServer() {
	servState := loadServerState()

	ticker := time.NewTicker(5 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <- ticker.C:
				ums := servState.usrManager.(*userManagerState)
				ums.mutex.Lock()
				usersArr := make([]user, len(ums.users))
				i := 0
				for _, value := range ums.users {
					usersArr[i] = value
					i++
				}
				exported := exportUsers(usersArr)
				// TODO(vmykh): wtf is 0644 ?
				dir, err := os.Getwd()
				utils.PanicIfError(err)
				fmt.Println(exported)
				err = ioutil.WriteFile(dir + "/server/users.dat", []byte(exported), 0644)
				utils.PanicIfError(err)
				fmt.Println("File Written")
				ums.mutex.Unlock()
			case <- quit:
				ticker.Stop()
				return
			}
		}
	}()

	fmt.Println(servState.usrManager)

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

	dir, err := os.Getwd()
	utils.PanicIfError(err)
	userFileBytes, err := ioutil.ReadFile(dir + "/server/users.dat")
	users := parseUsers(string(userFileBytes))
	um := createUserManager(users)

	return &server{serverPriv, tsPubKey, tsTcpAddr, trentPub, um}
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
	fmt.Printf("r1 = %d\n", r1)

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

	startSession(protocol.NewSecureConn(conn, sKey), &userHandlerState{serverState.usrManager, nil})
}
func startSession(conn net.Conn, handler userHandler) {
	defer conn.Close()

	for {
		msg, err := protocol.ReadNetworkMessage(conn)
		if err != nil {
			fmt.Println("error: " + err.Error())
			break
		}
		var resMsg string
		switch m := msg.(type) {
		case *protocol.LoginRequest:
			err = handler.login(m.Login, m.Password)
			if err != nil {
				resMsg = err.Error()
			} else {
				resMsg = "Successful Login"
			}
		case *protocol.ChangePasswordRequest:
			err = handler.changePassword(m.Oldpass, m.Newpass)
			if err != nil {
				resMsg = err.Error()
			} else {
				resMsg = "Password changed successfully"
			}
		case *protocol.AddUserRequest:
			err = handler.addUser(m.Uname, m.Upass)
			if err != nil {
				resMsg = err.Error()
			} else {
				resMsg = "User was added successfully"
			}
		case *protocol.BlockUserRequest:
			err = handler.blockUser(m.Uname)
			if err != nil {
				resMsg = err.Error()
			} else {
				resMsg = "User was banned successfully"
			}
		case *protocol.FetchDocumentRequest:
			doc, err := handler.fetchDocument(m.Docname)
			if err != nil {
				resMsg = err.Error()
			} else {
				resMsg = doc
			}
		case *protocol.CloseSessionRequest:
			break;
		default:
			resMsg = "Request not recognized"
		}

		resBytes, err := protocol.ConstructNetworkMessage(&protocol.ServerResponse{resMsg})
		utils.PanicIfError(err)
		_, err = conn.Write(resBytes)
		utils.PanicIfError(err)
	}
}

// region business logic
type userHandler interface {
	login(login string, password string) error

	addUser(uname string, upass string) error

	blockUser(uname string) error

	changePassword(oldpass string, newpass string) error

	fetchDocument(name string) (string, error)
}

type userHandlerState struct {
	usrManager userManager
	usr *user
}

func (uh *userHandlerState) login(login string, password string) error {
	usr, err := uh.usrManager.GetUser(login)
	if err != nil {
		return errors.New("No Such User")
	}

	if password != usr.Password {
		return errors.New("Password is not correct")
	}

	uh.usr = &usr
	return nil
}

func (uh *userHandlerState) addUser(uname string, upass string) error {
	if uh.usr == nil {
		return errors.New("Not authenticated")
	}

	if !uh.usr.IsAdmin {
		return errors.New("Operation is not allowed")
	}

	err := uh.usrManager.AddUser(user{uname, upass, false, false})
	if err != nil {
		return err
	}

	return nil
}

func (uh *userHandlerState) blockUser(uname string) error {
	if uh.usr == nil {
		return errors.New("Not authenticated")
	}

	if !uh.usr.IsAdmin {
		return errors.New("Operation is not allowed")
	}

	usr, err := uh.usrManager.GetUser(uname)
	if err != nil {
		return err
	}
	usr.IsBanned = true
	err = uh.usrManager.UpdateUser(usr)
	if err != nil {
		return err
	}

	return nil
}

func (uh *userHandlerState) changePassword(oldpass string, newpass string) error {
	if uh.usr == nil {
		return errors.New("Not authenticated")
	}

	if uh.usr.Password != oldpass {
		return errors.New("Old password is not correct")
	}

	uh.usr.Password = newpass
	err := uh.usrManager.UpdateUser(*uh.usr)
	if err != nil {
		return err
	}

	return nil
}

func (uh *userHandlerState) fetchDocument(name string) (string, error) {
	return "bla-bla-bla-document", nil
}
// endregion
