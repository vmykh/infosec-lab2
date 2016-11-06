package protocol

import (
	"crypto/rsa"
	//"time"
	"encoding/binary"
	"github.com/vmykh/infosec/lab2/utils"
	"bytes"
	//"fmt"
	"crypto/sha256"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	//"github.com/vmykh/infosec/lab2/rsautils"
	"encoding/gob"
	"encoding/json"
	//"go/types"
	"reflect"
	"io"
	"errors"
)

const (
	TimeRequestCode = 1
	TimeResponseCode = 2

	TrentRequestCode = 3
	TrentResponseCode = 4

	PeersConnectRequest = 5
	PeersConnectResponse = 6
)

const (
	MaxMessageSize = 65535
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
	ClientID string
	ClientPublicKey string
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
func VerifyCertificate(cert *Certificate, tsPub *rsa.PublicKey) (error) {
	hashed := hashCertificateInfoWithSha256(cert.ClientID, cert.ClientPublicKey, cert.Timestamp)
	signatureBytes, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return err
	}

 	return rsa.VerifyPKCS1v15(tsPub, crypto.SHA256, hashed, signatureBytes)
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

func parsePublikKey(keyStr string) (*rsa.PublicKey, error) {
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
	default:
		return nil, errors.New("Invalid message code")
	}
}
// endregion



//func CreateMessage(int,msg interface{}) []byte {
//
//}

// RC4
// Tiny Coding algorithm
// intel libraries


// reverse engineering         and exploit database   use kali linux
