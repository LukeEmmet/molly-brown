package main

import (
	"errors"
	"github.com/BurntSushi/toml"
)

type Config struct {
	Port             int
	Hostname         string
	CertPath         string
	KeyPath          string
	DocBase          string
	HomeDocBase      string
	GeminiExt        string
	DefaultLang      string
	LogPath          string
	TempRedirects    map[string]string
	PermRedirects    map[string]string
	MimeOverrides    map[string]string
	CGIPaths         []string
	SCGIPaths        map[string]string
	CertificateZones map[string][]string
	DirectorySort    string
	DirectoryReverse bool
	DirectoryTitles  bool
}

type MollyFile struct {
	GeminiExt        string
	DefaultLang      string
	DirectorySort    string
	DirectoryReverse bool
	DirectoryTitles  bool
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
	config.GeminiExt = "gmi"
	config.DefaultLang = ""
	config.LogPath = "molly.log"
	config.TempRedirects = make(map[string]string)
	config.PermRedirects = make(map[string]string)
	config.CGIPaths = make([]string, 0)
	config.SCGIPaths = make(map[string]string)
	config.DirectorySort = "Name"

	// Return defaults if no filename given
	if filename == "" {
		return config, nil
	}

	// Attempt to overwrite defaults from file
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return config, err
	}

	// Validate pseudo-enums
	switch config.DirectorySort {
	case "Name", "Size", "Time":
	default:
		return config, errors.New("Invalid DirectorySort value.")
	}

	return config, nil
}
