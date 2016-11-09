package main

import (
	"sync"
	"github.com/vmykh/infosec/lab2/server"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(1)
	//go startTrent(wg)
	go startServer(wg)

	wg.Wait()
}

func startServer(wg sync.WaitGroup) {
	server.StartServer()
	defer wg.Done()
}
