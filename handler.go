package main

import (
		"bufio"
		"fmt"
		"net"
		"net/url"
)

func handleGeminiRequest(conn net.Conn, config Config) {
	defer conn.Close()

	// Read request
	reader := bufio.NewReaderSize(conn, 1024)
	request, overflow, err := reader.ReadLine()
	if overflow {
		conn.Write([]byte("59 Request too long!r\n"))
		return
	} else if err != nil {
		conn.Write([]byte("40 Unknown error reading request!r\n"))
		return
	}

	// Parse request as URL
	URL, err := url.Parse(string(request))
	if err != nil {
		conn.Write([]byte("59 Error parsing URL!r\n"))
		return
	}

	// Generic response
	conn.Write([]byte("20 text/gemini\r\n"))
	body := fmt.Sprintf("Molly at %s says \"Hi!\" from %s.\n", URL.Host, URL.Path)
	conn.Write([]byte(body))
}
