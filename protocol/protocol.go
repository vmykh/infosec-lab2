package protocol

import (
	"crypto/rsa"
	"encoding/binary"
	"github.com/vmykh/infosec/lab2/utils"
	"bytes"
	"crypto/sha256"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"encoding/gob"
	"encoding/json"
	"reflect"
	"io"
	"errors"
	//"math"
	"net"
	"time"
	//"math"
)

const (
	TimeRequestCode = 1
	TimeResponseCode = 2

	TrentRequestCode = 3
	TrentResponseCode = 4

	PeersConnectRequestCode = 5
	PeersConnectResponseCode = 6

	LoginRequestCode = 10
	ChangePasswordRequestCode = 11
	AddUserRequestCode = 12
	BlockUserRequestCode = 13
	FetchDocumentRequestCode = 14
	CloseSessionRequestCode = 15

	ServerResponseCode = 20
)

const (
	MaxMessageSize = 65535
	CertificateExpirationPeriod = int64(24 * 30 * time.Hour)   // 1 month
)

type TrentRequest struct {
	ClientID string
	ServerID string
}

type TrentResponse struct {
	ClientCert Certificate
	ServerCert Certificate
}

// region time
type TimeRequest struct {
	Seed int64
}

type TimeResponse struct {
	Timestamp int64
	Signature string
}

func SignTimestamp(timestamp int64, seed int64, priv *rsa.PrivateKey) string {
	seedBytes := int64ToBytes(seed)
	timestampBytes := int64ToBytes(timestamp)

	bytesToHash := make([]byte, 16)
	copy(bytesToHash[:8], seedBytes)
	copy(bytesToHash[8:], timestampBytes)

	hashed := sha256.Sum256(bytesToHash)


	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])

	// debug
	fmt.Printf("bytes to send - signature: %X\n", signature)

	utils.PanicIfError(err)

	return base64.StdEncoding.EncodeToString(signature)
}

func VerifyTimestamp(timestamp int64, seed int64, signature string, pub *rsa.PublicKey) (err error) {
	seedBytes := int64ToBytes(seed)
	timestampBytes := int64ToBytes(timestamp)

	bytesToHash := make([]byte, 16)
	copy(bytesToHash[:8], seedBytes)
	copy(bytesToHash[8:], timestampBytes)

	hashed := sha256.Sum256(bytesToHash)

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)

	fmt.Printf("bytes received - signature: %X\n", signatureBytes)

	if (err != nil) {
		return
	}

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signatureBytes)
	return
}

func int64ToBytes(n int64) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, n)

	utils.PanicIfError(err)

	return buf.Bytes()
}
// endregion

// region certificate
type Certificate struct {
	ID        string
	Pub       string
	Timestamp int64
	Signature string
}

func CreateCertificate(id string, pubKey *rsa.PublicKey, timestamp int64, tsPriv *rsa.PrivateKey) (*Certificate, error){
	keyBase64, err := marshalPublikKey(pubKey)
	if err != nil {
		return nil, err
	}

	hashed := hashCertificateInfoWithSha256(id, keyBase64, timestamp)
	signature, err := rsa.SignPKCS1v15(rand.Reader, tsPriv, crypto.SHA256, hashed)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return &Certificate{id, keyBase64, timestamp, signatureBase64}, nil
}

// TODO(vmykh): add timestamp checking
func VerifyCertificate(cert *Certificate, tsPub *rsa.PublicKey, currentTimestamp int64) (error) {
	hashed := hashCertificateInfoWithSha256(cert.ID, cert.Pub, cert.Timestamp)
	signatureBytes, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return err
	}

 	err = rsa.VerifyPKCS1v15(tsPub, crypto.SHA256, hashed, signatureBytes)
	if err != nil {
		return err
	}

	delta := cert.Timestamp - currentTimestamp
	var absDelta int64
	if delta < 0 {
		absDelta = -absDelta
	}
	if absDelta > CertificateExpirationPeriod {
		return errors.New("Certificate is expired")
	}

	return nil
}

func hashCertificateInfoWithSha256(id string, keyBase64 string, timestamp int64) []byte {
	buf := new(bytes.Buffer)
	buf.Write([]byte(id))
	buf.Write([]byte(keyBase64))
	err := binary.Write(buf, binary.BigEndian, timestamp)
	utils.PanicIfError(err)

	hashed := sha256.Sum256(buf.Bytes())
	return hashed[:]
}

// TODO(vmykh): marshal public key in more interoperable way (maybe just as two numbers? bit int -> to string)
// also as json subobject {}
func marshalPublikKey(key *rsa.PublicKey) (string, error) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(key)
	if (err != nil) {
		return "", err
	}

	b64encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return b64encoded, nil
}

func ParsePublikKey(keyStr string) (*rsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(keyBytes)
	decoder := gob.NewDecoder(reader)

	pubParsed := new(rsa.PublicKey)
	decoder.Decode(pubParsed)
	return pubParsed, nil
}
// endregion

// region common
func ConstructNetworkMessage(m interface{}) ([]byte, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	
	msgSize := len(jsonBytes)
	if msgSize > MaxMessageSize {
		errorMsg := fmt.Sprintf("Protocol Error. Max Allowed Message Size = %d. " +
			"Actual Message size = %d\n", MaxMessageSize, msgSize)
		return nil, errors.New(errorMsg)
		
	}

	networkMsgBytes := make([]byte, msgSize + 3)

	msgCode, err := determineMsgCode(m)
	if err != nil {
		return nil, err
	}
	networkMsgBytes[0] =  byte(msgCode)

	msgLengthBuf := new(bytes.Buffer)
	binary.Write(msgLengthBuf, binary.BigEndian, uint16(msgSize))
	msgLengthBytes := msgLengthBuf.Bytes()
	copy(networkMsgBytes[1:3], msgLengthBytes)

	copy(networkMsgBytes[3:], jsonBytes)

	return networkMsgBytes, nil
}

func ReadNetworkMessage(reader io.Reader) (interface{}, error) {
	metaInfo, err := utils.ReadExactly(3, reader)
	if err != nil {
		return nil, err
	}

	msgCode := int(metaInfo[0])
	var msgLen uint16
	err = binary.Read(bytes.NewReader(metaInfo[1:3]), binary.BigEndian, &msgLen)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	readJsonBytes, err := utils.ReadExactly(int(msgLen), reader)
	if err != nil {
		return nil, err
	}

	target, err := createTargetType(msgCode)
	err = json.Unmarshal(readJsonBytes, target)
	if err != nil {
		return nil, err
	}

	return target, nil
}

// TODO(vmykh): maybe refactor next 2 functions in some way? like using some kind of bidirectional map
func determineMsgCode(m interface{}) (int, error){
	switch m.(type) {
	case *TimeRequest:
		return TimeRequestCode, nil
	case *TimeResponse:
		return TimeResponseCode, nil
	case *TrentRequest:
		return TrentRequestCode, nil
	case *TrentResponse:
		return TrentResponseCode, nil
	case *PeersConnectRequest:
		return PeersConnectRequestCode, nil
	case *PeersConnectResponse:
		return PeersConnectResponseCode, nil

	// session
	case *LoginRequest:
		return LoginRequestCode, nil
	case *ChangePasswordRequest:
		return ChangePasswordRequestCode, nil
	case *AddUserRequest:
		return AddUserRequestCode, nil
	case *BlockUserRequest:
		return BlockUserRequestCode, nil
	case *FetchDocumentRequest:
		return FetchDocumentRequestCode, nil
	case *CloseSessionRequest:
		return CloseSessionRequestCode, nil
	case *ServerResponse:
		return ServerResponseCode, nil

	default:
		return 0, errors.New("Cannot determine message code for: " + reflect.TypeOf(m).String())
	}
}

// TODO(vmykh): maybe call panic() instead of returing error ?
func createTargetType(msgCode int) (interface{}, error) {
	switch msgCode {
	case TimeRequestCode:
		return new(TimeRequest), nil
	case TimeResponseCode:
		return new(TimeResponse), nil
	case TrentRequestCode:
		return new(TrentRequest), nil
	case TrentResponseCode:
		return new(TrentResponse), nil
	case PeersConnectRequestCode:
		return new(PeersConnectRequest), nil
	case PeersConnectResponseCode:
		return new(PeersConnectResponse), nil

	// session
	case LoginRequestCode:
		return new(LoginRequest), nil
	case ChangePasswordRequestCode:
		return new(ChangePasswordRequest), nil
	case AddUserRequestCode:
		return new(AddUserRequest), nil
	case BlockUserRequestCode:
		return new(BlockUserRequest), nil
	case FetchDocumentRequestCode:
		return new(FetchDocumentRequest), nil
	case CloseSessionRequestCode:
		return new(CloseSessionRequest), nil
	case ServerResponseCode:
		return new(ServerResponse), nil
	default:
		return nil, errors.New("Invalid message code")
	}
}
// endregion

// region peers connection
type PeersConnectRequest struct {
	ClientCert Certificate
	R1 string
}

type PeersConnectResponse struct {
	F1 string
	R2 string
}

func EncryptNumber(n int32, pub *rsa.PublicKey) string {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, n)
	utils.PanicIfError(err)

	label := make([]byte, 0)
	cipherBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, buf.Bytes(), label)
	utils.PanicIfError(err)

	return base64.StdEncoding.EncodeToString(cipherBytes)
}

func DecryptNumber(cipher string, priv *rsa.PrivateKey) int32 {
	cipherBytes, err := base64.StdEncoding.DecodeString(cipher)
	utils.PanicIfError(err)

	label := make([]byte, 0)
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherBytes, label)
	utils.PanicIfError(err)

	var n int32
	err = binary.Read(bytes.NewReader(decryptedBytes), binary.BigEndian, &n)
	utils.PanicIfError(err)

	return n
}

// TODO(vmykh): refactor this function to using some strategy maybe, because now it's hardcoded which is not good
func CreateSymmetricKey(r1 int32, r2 int32) byte {
	sum := r1 + r2
	var base int32
	if (sum >= 0) {
		base = sum
	} else {
		base = -sum
	}
	return byte(base % 256)
}


// region secure connection (actually not secure at all)
// TODO(vmykh): maybe it can be done using embedding (it could reduce amount of code)
type SecureConn struct {
	conn net.Conn
	shift byte
}

func NewSecureConn(conn net.Conn, shift byte) *SecureConn {
	return &SecureConn{conn, shift}
}

func (sc *SecureConn) Read(b []byte) (int, error) {
	encryptedBytes := make([]byte, len(b))
	n, err := sc.conn.Read(encryptedBytes)
	if err != nil {
		return 0, err
	}

	for i := 0; i < n; i++ {
		b[i] = encryptedBytes[i] - sc.shift
	}

	return n, nil
}

func (sc *SecureConn) Write(b []byte) (int, error) {
	inputLen := len(b)
	encryptedBytes := make([]byte, inputLen)
	for i := 0; i < inputLen; i++ {
		encryptedBytes[i] = b[i] + sc.shift
	}

	n, err := sc.conn.Write(encryptedBytes)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (sc *SecureConn) Close() error {
	return sc.conn.Close()
}

func (sc *SecureConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

func (sc *SecureConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

func (sc *SecureConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

func (sc *SecureConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

func (sc *SecureConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}
// endregion

// region session
type LoginRequest struct {
	Login string
	Password string
}

type ChangePasswordRequest struct{
	Oldpass string
	Newpass string

}

type AddUserRequest struct {
	Uname string
	Upass string
}

type BlockUserRequest struct {
	Uname string
}

type FetchDocumentRequest struct {
	Docname string
}

type CloseSessionRequest struct {
}

type ServerResponse struct {
	Message string
}

// endregion

//func CreateMessage(int,msg interface{}) []byte {
//
//}

// RC4
// Tiny Coding algorithm
// intel libraries


// reverse engineering         and exploit database   use kali linux
