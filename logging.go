package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	Time       time.Time
	RemoteAddr net.Addr
	RequestURL string
	Status     int
}

func writeLogEntry(fp *os.File, entry LogEntry) {
	var line string
	line = entry.Time.Format(time.RFC3339)
	// Trim port from remote address
	addr := entry.RemoteAddr.String()
	addr = addr[0:strings.LastIndex(addr, ":")]
	line += "\t" + addr
	line += "\t" + strconv.Itoa(entry.Status)
	line += "\t" + entry.RequestURL
	line += "\n"
	fp.WriteString(line)
}
