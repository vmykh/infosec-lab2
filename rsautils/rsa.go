package rsautils

import (
	"github.com/vmykh/infosec/lab2/utils"
	"os"
	"encoding/gob"
	"crypto/rsa"
	"crypto/rand"
)

func GenerateKey() (*rsa.PrivateKey) {
	reader := rand.Reader
	bitSize := 512
	key, err := rsa.GenerateKey(reader, bitSize)
	utils.PanicIfError(err)
	return key;
}

func SaveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	utils.PanicIfError(err)
	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	utils.PanicIfError(err)
	outFile.Close()
}

func LoadKey(fileName string, key interface{}) {
	inFile, err := os.Open(fileName)
	utils.PanicIfError(err)
	decoder := gob.NewDecoder(inFile)
	err = decoder.Decode(key)
	utils.PanicIfError(err)
	inFile.Close()
}
