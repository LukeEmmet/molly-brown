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
	TempRedirects      map[string]string
	PermRedirects      map[string]string
	CGIPath            string
	SCGIPaths          map[string]string
}

func getConfig(filename string) (Config, error) {

	var config Config

	// Defaults
	config.Port = 1965
	config.Hostname = "localhost"
	config.CertPath = "cert.pem"
	config.KeyPath = "key.pem"
	config.DocBase = "/var/gemini/"
	config.HomeDocBase = "users"
	config.LogPath = "molly.log"
	config.TempRedirects = make(map[string]string)
	config.PermRedirects = make(map[string]string)
	config.CGIPath = "^/var/gemini/cgi-bin/"
	config.SCGIPaths = make(map[string]string)

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
