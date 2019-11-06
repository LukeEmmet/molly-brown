package main

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	Port           	   int
	Hostname       	   string
	CertPath           string
	KeyPath            string
	DocBase            string
	HomeDocBase        string
	LogPath            string
}

func getConfig(filename string) (Config, error) {

	var config Config

	// Defaults
	config.Port = 196
	config.Hostname = "localhost"
	config.CertPath = "cert.pem"
	config.KeyPath = "key.pem"
	config.DocBase = "/var/gemini/"
	config.HomeDocBase = "users"
	config.LogPath = "molly.log"

	// Return defaults if no filename given
	if filename == "" {
		return config, nil
	}

	// Attempt to overwrite defaults from file
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}
