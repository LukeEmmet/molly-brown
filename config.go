package main

import (
	"errors"
	"log"
	"os"
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

func parseMollyFiles(path string, config *Config, errorLog *log.Logger) {
	// Replace config variables which use pointers with new ones,
	// so that changes made here aren't reflected everywhere.
	newTempRedirects := make(map[string]string)
	for key, value := range config.TempRedirects {
		newTempRedirects[key] = value
	}
	config.TempRedirects = newTempRedirects
	newPermRedirects := make(map[string]string)
	for key, value := range config.PermRedirects {
		newPermRedirects[key] = value
	}
	config.PermRedirects = newPermRedirects
	newMimeOverrides := make(map[string]string)
	for key, value := range config.MimeOverrides {
		newMimeOverrides[key] = value
	}
	config.MimeOverrides = newMimeOverrides
	newCertificateZones := make(map[string][]string)
	for key, value := range config.CertificateZones {
		newCertificateZones[key] = value
	}
	config.CertificateZones = newCertificateZones
	// Initialise MollyFile using main Config
	var mollyFile MollyFile
	mollyFile.GeminiExt = config.GeminiExt
	mollyFile.DefaultLang = config.DefaultLang
	mollyFile.DirectorySort = config.DirectorySort
	mollyFile.DirectoryReverse = config.DirectoryReverse
	mollyFile.DirectoryTitles = config.DirectoryTitles
	// Build list of directories to check
	var dirs []string
	dirs = append(dirs, path)
	for {
		if path == filepath.Clean(config.DocBase) {
			break
		}
		subpath := filepath.Dir(path)
		dirs = append(dirs, subpath)
		path = subpath
	}
	// Parse files in reverse order
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		// Break out of the loop if a directory doesn't exist
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			break
		}
		// Construct path for a .molly file in this dir
		mollyPath := filepath.Join(dir, ".molly")
		_, err = os.Stat(mollyPath)
		if err != nil {
			continue
		}
		// If the file exists and we can read it, try to parse it
		_, err = toml.DecodeFile(mollyPath, &mollyFile)
		if err != nil {
			errorLog.Println("Error parsing .molly file " + mollyPath + ": " + err.Error())
			continue
		}
		// Overwrite main Config using MollyFile
		config.GeminiExt = mollyFile.GeminiExt
		config.DefaultLang = mollyFile.DefaultLang
		config.DirectorySort = mollyFile.DirectorySort
		config.DirectoryReverse = mollyFile.DirectoryReverse
		config.DirectoryTitles = mollyFile.DirectoryTitles
		for key, value := range mollyFile.TempRedirects {
			config.TempRedirects[key] = value
		}
		for key, value := range mollyFile.PermRedirects {
			config.PermRedirects[key] = value
		}
		for key, value := range mollyFile.MimeOverrides {
			config.MimeOverrides[key] = value
		}
		for key, value := range mollyFile.CertificateZones {
			config.CertificateZones[key] = value
		}
	}
}
