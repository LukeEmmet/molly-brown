package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
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
		os.Exit(1)
	}

	// Read TLS files, create TLS config
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		log.Fatal(err)
	}
	tlscfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12,
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", ":1965", tlscfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	// Infinite serve loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleGeminiRequest(conn, config)
	}

}
