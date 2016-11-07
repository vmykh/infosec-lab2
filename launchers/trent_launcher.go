package main

import (
	"sync"
	"github.com/vmykh/infosec/lab2/trent"
	"github.com/vmykh/infosec/lab2/timeprovider"
	"github.com/vmykh/infosec/lab2/server"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(2)
	//go startTrent(wg)
	go startTimeserver(wg)
	go startTrent(wg)
	go startServer(wg)

	wg.Wait()
}

func startTrent(wg sync.WaitGroup) {
	trent.StartTrent()
	defer wg.Done()
}

func startTimeserver(wg sync.WaitGroup) {
	timeprovider.StartTimeserver()
	defer wg.Done()
}

func startServer(wg sync.WaitGroup) {
	server.StartServer()
	defer wg.Done()
}
