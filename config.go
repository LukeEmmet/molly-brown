package main

import (
	"errors"
	"path/filepath"
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
	AccessLog        string
	ErrorLog         string
	ReadMollyFiles   bool
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
	TempRedirects    map[string]string
	PermRedirects    map[string]string
	MimeOverrides    map[string]string
	CertificateZones map[string][]string
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
	config.AccessLog = "access.log"
	config.ErrorLog = "error.log"
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

	// Expand CGI paths
	var cgiPaths []string
	for _, cgiPath := range config.CGIPaths {
		expandedPaths, err := filepath.Glob(cgiPath)
		if err != nil {
			return config, errors.New("Error expanding CGI path glob " + cgiPath + ": " + err.Error())
		}
		cgiPaths = append(cgiPaths, expandedPaths...)
	}
	config.CGIPaths = cgiPaths

	return config, nil
}
