package main

import (
		"bufio"
		"fmt"
		"net"
		"net/url"
		"time"
)

func handleGeminiRequest(conn net.Conn, config Config, logEntries chan LogEntry) {
	defer conn.Close()

	var log LogEntry
	log.Time = time.Now()
	log.RemoteAddr = conn.RemoteAddr()
	log.RequestURL = "-"
	log.Status = 0

	// Read request
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!r\n"))
		log.Status = 59
		logEntries <- log
		return
	} else if err != nil {
		conn.Write([]byte("40 Unknown error reading request!r\n"))
		log.Status = 40
		logEntries <- log
		return
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
		conn.Write([]byte("59 Error parsing URL!r\n"))
		log.Status = 59
		logEntries <- log
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
		logEntries <- log
		return
	}

	// Generic response
	conn.Write([]byte("20 text/gemini\r\n"))
	body := fmt.Sprintf("Molly at %s says \"Hi!\" from %s.\n", URL.Host, URL.Path)
	conn.Write([]byte(body))
	log.Status = 20
	logEntries <- log
}
