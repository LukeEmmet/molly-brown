package main

import (
		"bufio"
		"context"
		"crypto/sha256"
		"crypto/tls"
		"encoding/hex"
		"io"
		"net"
		"net/url"
		"os/exec"
		"strconv"
		"strings"
		"time"
)

func handleCGI(config Config, path string, URL *url.URL, log *LogEntry, conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)

	// Set environment variables
	vars := prepareCGIVariables(config, URL, conn, path)
	cmd.Env = []string{ }
	for key, value := range vars {
		cmd.Env = append(cmd.Env, key + "=" + value)
	}

	response, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		conn.Write([]byte("42 CGI process timed out!\r\n"))
		log.Status = 42
		return
	}
	if err != nil {
		conn.Write([]byte("42 CGI error!\r\n"))
		log.Status = 42
		return
	}
	// Extract response header
	header, _, err := bufio.NewReader(strings.NewReader(string(response))).ReadLine()
	status, err2 := strconv.Atoi(strings.Fields(string(header))[0])
	if err != nil || err2 != nil {
		conn.Write([]byte("42 CGI error!\r\n"))
		log.Status = 42
		return
	}
	log.Status = status
	// Write response
	conn.Write(response)
}

func handleSCGI(socket_path string, config Config, URL *url.URL, log *LogEntry, conn net.Conn) {

	// Connect to socket
	socket, err := net.Dial("unix", socket_path)
	if err != nil {
		conn.Write([]byte("42 Error connecting to SCGI service!\r\n"))
		log.Status = 42
		return
	}
	defer socket.Close()

	// Send variables
	vars := prepareSCGIVariables(config, URL, conn)
	length := 0
	for key, value := range(vars) {
		length += len(key)
		length += len(value)
		length += 2
	}
	socket.Write([]byte(strconv.Itoa(length) + ":"))
	for key, value := range(vars) {
		socket.Write([]byte(key + "\x00"))
		socket.Write([]byte(value + "\x00"))
	}
	socket.Write([]byte(","))

	// Read and relay response
	buffer := make([]byte, 1027)
	first := true
	for {
		n, err := socket.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			} else if !first {
				// Err
				conn.Write([]byte("42 Error reading from SCGI service!\r\n"))
				log.Status = 42
				return
			} else {
				break
			}
		}
		// Extract status code from first line
		if first {
			first = false
			lines := strings.SplitN(string(buffer), "\r\n", 2)
			status, err := strconv.Atoi(strings.Fields(lines[0])[0])
			if err != nil {
				conn.Write([]byte("42 CGI error!\r\n"))
				log.Status = 42
				return
			}
			log.Status = status
		}
		// Send to client
		conn.Write(buffer[:n])
	}
}

func prepareCGIVariables(config Config, URL *url.URL, conn net.Conn, path string) map[string]string {
	vars := prepareGatewayVariables(config, URL, conn)
	vars["GATEWAY_INTERFACE"] = "CGI/1.1"
	vars["SCRIPT_PATH"] = path
	return vars
}

func prepareSCGIVariables(config Config, URL *url.URL, conn net.Conn) map[string]string {
	vars := prepareGatewayVariables(config, URL, conn)
	vars["SCGI"] = "1"
	vars["CONTENT_LENGTH"] = "0"
	return vars
}

func prepareGatewayVariables(config Config, URL *url.URL, conn net.Conn) map[string]string {
	vars := make(map[string]string)
	vars["PATH_INFO"] = "/"
	vars["QUERY_STRING"] = URL.RawQuery
	vars["REMOTE_ADDR"] = conn.RemoteAddr().String()
	vars["REQUEST_METHOD"] = ""
	vars["SERVER_NAME"] = config.Hostname
	vars["SERVER_PORT"] = strconv.Itoa(config.Port)
	vars["SERVER_PROTOCL"] = "GEMINI"
	vars["SERVER_SOFTWARE"] = "MOLLY_BROWN"

	// Add TLS variables
	var tlsConn (*tls.Conn) = conn.(*tls.Conn)
	connState := tlsConn.ConnectionState()
//	vars["TLS_CIPHER"] = CipherSuiteName(connState.CipherSuite)

	// Add client cert variables
	clientCerts := connState.PeerCertificates
	if len(clientCerts) > 0 {
		cert := clientCerts[0]
		fingerprint := sha256.Sum256(cert.Raw)
		vars["TLS_CLIENT_HASH"] = hex.EncodeToString(fingerprint[:])
		vars["TLS_CLIENT_ISSUER"] = cert.Issuer.String()
		vars["TLS_CLIENT_ISSUER_CN"] = cert.Issuer.CommonName
		vars["TLS_CLIENT_SUBJECT"] = cert.Subject.String()
		vars["TLS_CLIENT_SUBJECT_CN"] = cert.Subject.CommonName
	}

	return vars
}
