package main

import (
	"fmt"
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/proxy"
	"goProxy/core/server"
	"io"
	"log"
	"os"
	"time"
)

var Fingerprint string = "Cloudflare"

func main() {
	proxy.Fingerprint = Fingerprint
	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	pnc.InitHndl()
	defer pnc.PanicHndl()
	log.SetOutput(io.Discard /*logFile*/)
	fmt.Println("Starting Proxy")
	config.Load()
	fmt.Println("Loaded Config")
	fmt.Println("Initialising")
	go server.Monitor()
	for !proxy.Initialised {
		time.Sleep(500 * time.Millisecond)
	}
	go server.Serve()
	select {}
}
