package main

import (
	"libs/gopass"
	"fmt"
	"os"
	"fmt"
)

func main() {
	fmt.Println("Enter password:")
	pass, err := gopass.GetPasswdMasked()
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("success: %s", pass)
}
