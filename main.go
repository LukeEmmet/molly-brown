package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	var conf_file string

	// Parse args and read config
	flag.StringVar(&conf_file, "c", "", "Path to config file")
	flag.Parse()
	if conf_file == "" {
		_, err := os.Stat("/etc/molly.conf")
		if err == nil {
			conf_file = "/etc/molly.conf"
		}
	}
	config, err := getConfig(conf_file)
	if err != nil {
		log.Fatal(err)
	}

	// Open log files
	errorLogFile, err := os.OpenFile(config.ErrorLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer errorLogFile.Close()
	accessLogFile, err := os.OpenFile(config.AccessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer accessLogFile.Close()

	// Read TLS files, create TLS config
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		log.Fatal(err)
	}
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(config.Port), tlscfg)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Start log handling routines
	accessLogEntries := make(chan LogEntry, 10)
	go func() {
		for {
			entry := <-accessLogEntries
			writeLogEntry(accessLogFile, entry)
		}
	}()
	errorLogEntries := make(chan string, 10)
	go func() {
		for {
			message := <-errorLogEntries
			errorLogFile.WriteString(time.Now().Format(time.RFC3339) + " " + message + "\n")
		}
	}()

	// Infinite serve loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleGeminiRequest(conn, config, accessLogEntries, errorLogEntries)
	}

}
