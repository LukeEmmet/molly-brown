package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

func main() {
	var conf_file string

	// Parse args and read config
	flag.StringVar(&conf_file, "c", "", "Path to config file")
	flag.Parse()
	if conf_file == "" {
		_, err := os.Stat("/etc/molly.conf")
		if !os.IsNotExist(err) {
			conf_file = "/etc/molly.conf"
		}
	}
	config, err := getConfig(conf_file)
	if err != nil {
		fmt.Println("Error reading config file " + conf_file)
		fmt.Println(err)
		os.Exit(1)
	}

	// Open logfile
	logfile, err := os.OpenFile(config.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file " + config.LogPath + ".")
		os.Exit(2)
	}
	defer logfile.Close()

	// Read TLS files, create TLS config
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		log.Fatal(err)
	}
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequestClientCert,
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":" + strconv.Itoa(config.Port), tlscfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	// Start log handling routine
	logEntries := make(chan LogEntry, 10)
	go func () {
		for {
			entry := <- logEntries
			writeLogEntry(logfile, entry)
		}
	}()

	// Infinite serve loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleGeminiRequest(conn, config, logEntries)
	}

}
