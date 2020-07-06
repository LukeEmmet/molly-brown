package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func handleCGI(config Config, path string, cgiPath string, URL *url.URL, log *LogEntry, errorLog *log.Logger, conn net.Conn) {
	// Find the shortest leading part of path which maps to an executable file.
	// Call this part scriptPath, and everything after it pathInfo.
	components := strings.Split(path, "/")
	scriptPath := ""
	pathInfo := ""
	matched := false
	for i := 0; i <= len(components); i++ {
		scriptPath = strings.Join(components[0:i], "/")
		pathInfo = strings.Join(components[i:], "/")
		if !strings.HasPrefix(scriptPath, cgiPath) {
			continue
		}
		info, err := os.Stat(scriptPath)
		if err != nil {
			break
		} else if info.IsDir() {
			continue
		} else if info.Mode().Perm()&0555 == 0555 {
			matched = true
			break
		}
	}
	// If we didn't find a match, give up and let this request be handled as
	// if it were a static file
	if !matched {
		return
	}

	// Prepare environment variables
	vars := prepareCGIVariables(config, URL, conn, scriptPath, pathInfo)

	// Spawn process
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Env = []string{}
	for key, value := range vars {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	response, err := cmd.Output()

	if ctx.Err() == context.DeadlineExceeded {
		errorLog.Println("Terminating CGI process " + path + " due to exceeding 10 second runtime limit.")
		conn.Write([]byte("42 CGI process timed out!\r\n"))
		log.Status = 42
		return
	}
	if err != nil {
		errorLog.Println("Error running CGI program " + path + ": " + err.Error())
		if err, ok := err.(*exec.ExitError); ok {
			errorLog.Println("↳ stderr output: " + string(err.Stderr))
		}
		conn.Write([]byte("42 CGI error!\r\n"))
		log.Status = 42
		return
	}
	// Extract response header
	header, _, err := bufio.NewReader(strings.NewReader(string(response))).ReadLine()
	status, err2 := strconv.Atoi(strings.Fields(string(header))[0])
	if err != nil || err2 != nil {
		errorLog.Println("Unable to parse first line of output from CGI process " + path + " as valid Gemini response header.  Line was: " + string(header))
		conn.Write([]byte("42 CGI error!\r\n"))
		log.Status = 42
		return
	}
	log.Status = status
	// Write response
	conn.Write(response)
}

func handleSCGI(URL *url.URL, scgiPath string, scgiSocket string, config Config, log *LogEntry, errorLog *log.Logger, conn net.Conn) {

	// Connect to socket
	socket, err := net.Dial("unix", scgiSocket)
	if err != nil {
		errorLog.Println("Error connecting to SCGI socket " + scgiSocket + ": " + err.Error())
		conn.Write([]byte("42 Error connecting to SCGI service!\r\n"))
		log.Status = 42
		return
	}
	defer socket.Close()

	// Send variables
	vars := prepareSCGIVariables(config, URL, scgiPath, conn)
	length := 0
	for key, value := range vars {
		length += len(key)
		length += len(value)
		length += 2
	}
	socket.Write([]byte(strconv.Itoa(length) + ":"))
	for key, value := range vars {
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
				errorLog.Println("Error reading from SCGI socket " + scgiSocket + ": " + err.Error())
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

func prepareCGIVariables(config Config, URL *url.URL, conn net.Conn, script_path string, path_info string) map[string]string {
	vars := prepareGatewayVariables(config, URL, conn)
	vars["GATEWAY_INTERFACE"] = "CGI/1.1"
	vars["SCRIPT_PATH"] = script_path
	vars["PATH_INFO"] = path_info
	return vars
}

func prepareSCGIVariables(config Config, URL *url.URL, scgiPath string, conn net.Conn) map[string]string {
	vars := prepareGatewayVariables(config, URL, conn)
	vars["SCGI"] = "1"
	vars["CONTENT_LENGTH"] = "0"
	vars["SCRIPT_PATH"] = scgiPath
	vars["PATH_INFO"] = URL.Path[len(scgiPath):]
	return vars
}

func prepareGatewayVariables(config Config, URL *url.URL, conn net.Conn) map[string]string {
	vars := make(map[string]string)
	vars["QUERY_STRING"] = URL.RawQuery
	vars["REMOTE_ADDR"] = conn.RemoteAddr().String()
	vars["REQUEST_METHOD"] = ""
	vars["SERVER_NAME"] = config.Hostname
	vars["SERVER_PORT"] = strconv.Itoa(config.Port)
	vars["SERVER_PROTOCOL"] = "GEMINI"
	vars["SERVER_SOFTWARE"] = "MOLLY_BROWN"

	// Add TLS variables
	var tlsConn (*tls.Conn) = conn.(*tls.Conn)
	connState := tlsConn.ConnectionState()
	//	vars["TLS_CIPHER"] = CipherSuiteName(connState.CipherSuite)

	// Add client cert variables
	clientCerts := connState.PeerCertificates
	if len(clientCerts) > 0 {
		cert := clientCerts[0]
		vars["TLS_CLIENT_HASH"] = getCertFingerprint(cert)
		vars["TLS_CLIENT_ISSUER"] = cert.Issuer.String()
		vars["TLS_CLIENT_ISSUER_CN"] = cert.Issuer.CommonName
		vars["TLS_CLIENT_SUBJECT"] = cert.Subject.String()
		vars["TLS_CLIENT_SUBJECT_CN"] = cert.Subject.CommonName
	}
	return vars
}
