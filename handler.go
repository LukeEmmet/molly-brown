package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func handleGeminiRequest(conn net.Conn, config Config, accessLogEntries chan LogEntry, errorLog *log.Logger) {
	defer conn.Close()
	var tlsConn (*tls.Conn) = conn.(*tls.Conn)
	var log LogEntry
	log.Time = time.Now()
	log.RemoteAddr = conn.RemoteAddr()
	log.RequestURL = "-"
	log.Status = 0
	defer func() { accessLogEntries <- log }()

	// Read request
	URL, err := readRequest(conn, &log, errorLog)
	if err != nil {
		return
	}

	// Enforce client certificate validity
	clientCerts := tlsConn.ConnectionState().PeerCertificates
	enforceCertificateValidity(clientCerts, conn, &log)
	if log.Status != 0 {
		return
	}

	// Reject non-gemini schemes
	if URL.Scheme != "gemini" {
		conn.Write([]byte("53 No proxying to non-Gemini content!\r\n"))
		log.Status = 53
		return
	}

	// Reject requests for content from other servers
	if URL.Hostname() != config.Hostname || (URL.Port() != "" && URL.Port() != strconv.Itoa(config.Port)) {
		conn.Write([]byte("53 No proxying to other hosts or ports!\r\n"))
		log.Status = 53
		return
	}

	// Fail if there are dots in the path
	if strings.Contains(URL.Path, "..") {
		conn.Write([]byte("50 Your directory traversal technique has been defeated!\r\n"))
		log.Status = 50
		return
	}

	// Resolve URI path to actual filesystem path
	path := resolvePath(URL.Path, config)

	// Paranoid security measures:
	// Fail ASAP if the URL has mapped to a sensitive file
	if path == config.CertPath || path == config.KeyPath || path == config.AccessLog || path == config.ErrorLog || filepath.Base(path) == ".molly" {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}

	// Read Molly files
	if config.ReadMollyFiles {
		parseMollyFiles(path, &config, errorLog)
	}

	// Check whether this URL is in a certificate zone
	handleCertificateZones(URL, clientCerts, config, conn, &log)
	if log.Status != 0 {
		return
	}

	// Check for redirects
	handleRedirects(URL, config, conn, &log, errorLog)
	if log.Status != 0 {
		return
	}

	// Check whether this URL is mapped to an SCGI app
	for scgiPath, scgiSocket := range config.SCGIPaths {
		if strings.HasPrefix(URL.Path, scgiPath) {
			handleSCGI(URL, scgiPath, scgiSocket, config, &log, errorLog, conn)
			return
		}
	}

	// Check whether this URL is in a configured CGI path
	for _, cgiPath := range config.CGIPaths {
		if strings.HasPrefix(path, cgiPath) {
			handleCGI(config, path, cgiPath, URL, &log, errorLog, conn)
			if log.Status != 0 {
				return
			}
		}
	}

	// Fail if file does not exist or perms aren't right
	info, err := os.Stat(path)
	if os.IsNotExist(err) || os.IsPermission(err) {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	} else if err != nil {
		errorLog.Println("Error getting info for file " + path + ": " + err.Error())
		conn.Write([]byte("40 Temporary failure!\r\n"))
		log.Status = 40
		return
	} else if uint64(info.Mode().Perm())&0444 != 0444 {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}

	// Finally, serve the file or directory
	if info.IsDir() {
		serveDirectory(URL, path, &log, conn, config, errorLog)
	} else {
		serveFile(path, &log, conn, config, errorLog)
	}
}

func readRequest(conn net.Conn, log *LogEntry, errorLog *log.Logger) (*url.URL, error) {
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!\r\n"))
		log.Status = 59
		return nil, errors.New("Request too long")
	} else if err != nil {
		errorLog.Println("Error reading request: " + err.Error())
		conn.Write([]byte("40 Unknown error reading request!\r\n"))
		log.Status = 40
		return nil, errors.New("Error reading request")
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
		errorLog.Println("Error parsing request URL " + string(request) + ": " + err.Error())
		conn.Write([]byte("59 Error parsing URL!\r\n"))
		log.Status = 59
		return nil, errors.New("Bad URL in request")
	}
	log.RequestURL = URL.String()

	// Set implicit scheme
	if URL.Scheme == "" {
		URL.Scheme = "gemini"
	}

	return URL, nil
}

func resolvePath(path string, config Config) string {
	// Handle tildes
	if strings.HasPrefix(path, "/~") {
		bits := strings.Split(path, "/")
		username := bits[1][1:]
		new_prefix := filepath.Join(config.DocBase, config.HomeDocBase, username)
		path = strings.Replace(path, bits[1], new_prefix, 1)
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(config.DocBase, path)
	}
	return path
}

func handleRedirects(URL *url.URL, config Config, conn net.Conn, log *LogEntry, errorLog *log.Logger) {
	handleRedirectsInner(URL, config.TempRedirects, 30, conn, log, errorLog)
	handleRedirectsInner(URL, config.PermRedirects, 31, conn, log, errorLog)
}

func handleRedirectsInner(URL *url.URL, redirects map[string]string, status int, conn net.Conn, log *LogEntry, errorLog *log.Logger) {
	strStatus := strconv.Itoa(status)
	for src, dst := range redirects {
		compiled, err := regexp.Compile(src)
		if err != nil {
			errorLog.Println("Error compiling redirect regexp " + src + ": " + err.Error())
			continue
		}
		if compiled.MatchString(URL.Path) {
			URL.Path = compiled.ReplaceAllString(URL.Path, dst)
			conn.Write([]byte(strStatus + " " + URL.String() + "\r\n"))
			log.Status = status
			return
		}
	}
}

func serveDirectory(URL *url.URL, path string, log *LogEntry, conn net.Conn, config Config, errorLog *log.Logger) {
	// Redirect to add trailing slash if missing
	// (otherwise relative links don't work properly)
	if !strings.HasSuffix(URL.Path, "/") {
		conn.Write([]byte(fmt.Sprintf("31 %s\r\n", URL.String()+"/")))
		log.Status = 31
		return
	}
	// Check for index.gmi if path is a directory
	index_path := filepath.Join(path, "index."+config.GeminiExt)
	index_info, err := os.Stat(index_path)
	if err == nil && uint64(index_info.Mode().Perm())&0444 == 0444 {
		serveFile(index_path, log, conn, config, errorLog)
		// Serve a generated listing
	} else {
		listing, err := generateDirectoryListing(URL, path, config)
		if err != nil {
			errorLog.Println("Error generating listing for directory " + path + ": " + err.Error())
			conn.Write([]byte("40 Server error!\r\n"))
			log.Status = 40
			return
		}
		conn.Write([]byte("20 text/gemini\r\n"))
		log.Status = 20
		conn.Write([]byte(listing))
	}
}

func serveFile(path string, log *LogEntry, conn net.Conn, config Config, errorLog *log.Logger) {
	// Get MIME type of files
	ext := filepath.Ext(path)
	var mimeType string
	if ext == "."+config.GeminiExt {
		mimeType = "text/gemini"
	} else {
		mimeType = mime.TypeByExtension(ext)
	}
	// Override extension-based MIME type
	for pathRegex, newType := range config.MimeOverrides {
		overridden, err := regexp.Match(pathRegex, []byte(path))
		if err == nil && overridden {
			mimeType = newType
		}
	}
	// Set a generic MIME type if the extension wasn't recognised
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	// Add lang parameter
	if mimeType == "text/gemini" && config.DefaultLang != "" {
		mimeType += "; lang=" + config.DefaultLang
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		errorLog.Println("Error reading file " + path + ": " + err.Error())
		conn.Write([]byte("50 Error!\r\n"))
		log.Status = 50
		return
	}
	conn.Write([]byte(fmt.Sprintf("20 %s\r\n", mimeType)))
	log.Status = 20
	conn.Write(contents)
}
