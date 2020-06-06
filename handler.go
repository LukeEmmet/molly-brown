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
		"strings"
		"time"
)

func handleGeminiRequest(conn net.Conn, config Config, logEntries chan LogEntry) {
	defer conn.Close()
	var tlsConn (*tls.Conn) = conn.(*tls.Conn)
	var log LogEntry
	log.Time = time.Now()
	log.RemoteAddr = conn.RemoteAddr()
	log.RequestURL = "-"
	log.Status = 0
	defer func() { logEntries <- log }()

	// Read request
	URL, err := readRequest(conn, &log)
	if err != nil {
		return
	}

	clientCerts := tlsConn.ConnectionState().PeerCertificates
	// Check validity
	// This will fail if any of multiple certs are invalid
	// Maybe we should just require one valid?
	now := time.Now()
	for _, cert := range clientCerts {
		if now.Before(cert.NotBefore) {
			conn.Write([]byte("64 Client certificate not yet valid!\r\n"))
			log.Status = 64
			return
		} else if now.After(cert.NotAfter) {
			conn.Write([]byte("65 Client certificate has expired!\r\n"))
			log.Status = 65
			return
		}
	}

	// Reject non-gemini schemes
	if URL.Scheme != "gemini" {
		conn.Write([]byte("53 No proxying to non-Gemini content!\r\n"))
		log.Status = 53
		return
	}

	// Reject requests for content from other servers
	requestHostname := strings.Split(URL.Host, ":")[0] // Shave off port
	if requestHostname != config.Hostname {
		conn.Write([]byte("53 No proxying to other hosts!\r\n"))
		log.Status = 53
		return
	}

	// Fail if there are dots in the path
	if strings.Contains(URL.Path, "..") {
		conn.Write([]byte("50 Your directory traversal technique has been defeated!\r\n"))
		log.Status = 50
		return
	}

	// Check whether this URL is mapped to an SCGI app
	for scgi_url, scgi_socket := range config.SCGIPaths {
		fmt.Println(scgi_url, URL.Path)
	    matched, err := regexp.Match(scgi_url, []byte(URL.Path))
		if matched && err == nil {
		    fmt.Println("Matched:", scgi_url, scgi_socket)
			handleSCGI(scgi_socket, config, URL, &log, conn)
			return
		}
	}

	// Resolve URI path to actual filesystem path
	path, info, err := resolvePath(URL.Path, config)

	// Fail if file does not exist or perms aren't right
	if os.IsNotExist(err) || os.IsPermission(err) {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	} else if err != nil {
		conn.Write([]byte("40 Temporaray failure!\r\n"))
		log.Status = 40
		return
	} else if uint64(info.Mode().Perm())&0444 != 0444 {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}

	// Paranoid security measure:
	// Fail if the URL has mapped to our TLS files or the log
	if path == config.CertPath || path == config.KeyPath || path == config.LogPath {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}

	// Handle directories
	if info.IsDir() {
		// Redirect to add trailing slash if missing
		// (otherwise relative links don't work properly)
		if !strings.HasSuffix(URL.Path, "/") {
			conn.Write([]byte(fmt.Sprintf("31 %s\r\n", URL.String()+"/")))
			log.Status = 31
			return
		}
		// Check for index.gmi if path is a directory
		index_path := filepath.Join(path, "index.gmi")
		index_info, err := os.Stat(index_path)
		if err == nil && uint64(index_info.Mode().Perm())&0444 == 0444 {
			serveFile(index_path, &log, conn)
		// Serve a generated listing
		} else {
			conn.Write([]byte("20 text/gemini\r\n"))
			log.Status = 20
			conn.Write([]byte(generateDirectoryListing(path)))
		}
		return
	}

	// If this file is executable, get dynamic content
	inCGIPath, err := regexp.Match(config.CGIPath, []byte(path))
	if inCGIPath && info.Mode().Perm() & 0111 == 0111 {
		handleCGI(config, path, URL, &log, conn)
		return
	}

	// Otherwise, serve the file contents
	serveFile(path, &log, conn)
	return

}

func readRequest(conn net.Conn, log *LogEntry)  (*url.URL, error) {
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!\r\n"))
		log.Status = 59
		return nil, errors.New("Request too long")
	} else if err != nil {
		conn.Write([]byte("40 Unknown error reading request!\r\n"))
		log.Status = 40
		return nil, errors.New("Error reading request")
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
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

func resolvePath(path string, config Config) (string, os.FileInfo, error) {
	// Handle tildes
	if strings.HasPrefix(path, "/~") {
	    bits := strings.Split(path, "/")
		username := bits[1][1:]
		new_prefix := filepath.Join(config.DocBase, config.HomeDocBase, username)
		path = strings.Replace(path, bits[1], new_prefix, 1)
	} else {
		path = filepath.Join(config.DocBase, path)
	}
	// Make sure this file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}
	return path, info, nil
}

func generateDirectoryListing(path string) string {
	var listing string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	listing = "# Directory listing\n\n"
	for _, file := range files {
		// Skip dotfiles
		if strings.HasPrefix(file.Name(), ".") {
			continue
		}
		// Only list world readable files
		if uint64(file.Mode().Perm())&0444 != 0444 {
			continue
		}
		listing += fmt.Sprintf("=> %s %s\n", url.PathEscape(file.Name()), file.Name())
	}
	return listing
}

func serveFile(path string, log *LogEntry, conn net.Conn) {
	// Get MIME type of files
	ext := filepath.Ext(path)
	var mimeType string
	if ext == ".gmi" {
		mimeType = "text/gemini"
	} else {
		mimeType = mime.TypeByExtension(ext)
	}
	// Set a generic MIME type if the extension wasn't recognised
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		conn.Write([]byte("50 Error!\r\n"))
		log.Status = 50
	}
	conn.Write([]byte(fmt.Sprintf("20 %s\r\n", mimeType)))
	log.Status = 20
	conn.Write(contents)
}

