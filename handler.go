package main

import (
		"bufio"
		"fmt"
		"io/ioutil"
		"log"
		"mime"
		"net"
		"net/url"
		"os"
		"path/filepath"
		"strings"
		"time"
)

func handleGeminiRequest(conn net.Conn, config Config, logEntries chan LogEntry) {
	defer conn.Close()
	var log LogEntry
	log.Time = time.Now()
	log.RemoteAddr = conn.RemoteAddr()
	log.RequestURL = "-"
	log.Status = 0
	defer func() { logEntries <- log }()

	// Read request
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!r\n"))
		log.Status = 59
		return
	} else if err != nil {
		conn.Write([]byte("40 Unknown error reading request!r\n"))
		log.Status = 40
		return
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
		conn.Write([]byte("59 Error parsing URL!r\n"))
		log.Status = 59
		return
	}
	log.RequestURL = URL.String()

	// Set implicit scheme
	if URL.Scheme == "" {
		URL.Scheme = "gemini"
	}

	// Reject non-gemini schemes
	if URL.Scheme != "gemini" {
		conn.Write([]byte("53 No proxying to non-Gemini content!\r\n"))
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
	path := URL.Path
	if strings.HasPrefix(path, "/~") {
	    bits := strings.Split(path, "/")
		username := bits[1][1:]
		new_prefix := filepath.Join(config.DocBase, config.HomeDocBase, username)
		path = strings.Replace(path, bits[1], new_prefix, 1)
	} else {
		path = filepath.Join(config.DocBase, URL.Path)
	}

	// Fail if file does not exist or we may not read it
	info, err := os.Stat(path)
	if os.IsNotExist(err) || os.IsPermission(err) {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}

	// Handle URLS which map to a directory
	if info.IsDir() {
		// Redirect to add trailing slash if missing
		// (otherwise relative links don't work properly)
		if !strings.HasSuffix(URL.Path, "/") {
			conn.Write([]byte(fmt.Sprintf("31 %s\r\n", URL.String()+"/")))
			log.Status = 31
			return
		}
		// Add index.gmi to directory paths, if it exists
		index_path := filepath.Join(path, "index.gmi")
		index_info, err := os.Stat(index_path)
		if !os.IsNotExist(err) {
			path = index_path
			info = index_info
		}
	}
	// Fail if file is not world readable
	if uint64(info.Mode().Perm())&0444 != 0444 {
		conn.Write([]byte("51 Not found!\r\n"))
		log.Status = 51
		return
	}
	// If this is a directory, serve a generated listing
	if info.IsDir() {
		conn.Write([]byte("20 text/gemini\r\n"))
		log.Status = 20
		conn.Write([]byte(generateDirectoryListing(path)))
		return
	}

	// Get MIME type of files
	ext := filepath.Ext(path)
	var mimeType string
	if ext == ".gmi" {
		mimeType = "text/gemini"
	} else {
		mimeType = mime.TypeByExtension(ext)
	}
	fmt.Println(path, ext, mimeType)
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		conn.Write([]byte("50 Error!\r\n"))
		log.Status = 50
	} else {
		conn.Write([]byte(fmt.Sprintf("20 %s\r\n", mimeType)))
		log.Status = 20
		conn.Write(contents)
	}
	return

	// Generic response
	conn.Write([]byte("20 text/gemini\r\n"))
	body := fmt.Sprintf("Molly at %s says \"Hi!\" from %s.\n", URL.Host, URL.Path)
	conn.Write([]byte(body))
	log.Status = 20
}

func generateDirectoryListing(path string) string {
	var listing string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	listing = "# Directory listing\n\n"
	for _, file := range files {
		listing += fmt.Sprintf("=> %s %s\n", file.Name(), file.Name())
	}
	return listing
}
