package main

import (
	"sync"
	"github.com/vmykh/infosec/lab2/trent"
	"github.com/vmykh/infosec/lab2/timeprovider"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(1)
	//go startTrent(wg)
	go startTimeserver(wg)

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
