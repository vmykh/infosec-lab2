package utils

import (
	"fmt"
	"os"
	//"net"
	"io"
)

func ExitIfError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func PanicIfError(err error) {
	if err != nil {
		panic("Fatal error: " + err.Error())
	}
}

func Check(condition bool) {
	if !condition {
		panic("Checking condition failed")
	}
}

func ReadExactly(nBytes int, reader io.Reader) ([]byte, error) {
	buffer := make([]byte, nBytes)
	var alreadyRead int = 0
	for alreadyRead != nBytes {
		numRead, err := reader.Read(buffer[alreadyRead:])
		if err != nil {
			return nil, err
		}
		alreadyRead += numRead
	}
	return buffer, nil
}
