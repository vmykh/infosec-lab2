package main

import (
	"sync"
	"github.com/vmykh/infosec/lab2/trent"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(1)

	go startTrent(wg)

	wg.Wait()
}

func startTrent(wg sync.WaitGroup) {
	trent.StartTrent()
	defer wg.Done()
}
