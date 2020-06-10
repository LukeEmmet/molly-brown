package main

import (
	"net"
	"os"
	"strconv"
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
	line += "\t" + strconv.Itoa(entry.Status)
	line += "\t" + entry.RemoteAddr.String()
	line += "\t" + entry.RequestURL
	line += "\n"
	fp.WriteString(line)
}
