package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"time"
)

func enforceCertificateValidity(clientCerts []*x509.Certificate, conn net.Conn, log *LogEntry) {
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
}

func handleCertificateZones(URL *url.URL, clientCerts []*x509.Certificate, config Config, conn net.Conn, log *LogEntry) {
	authorised := true
	for zone, allowedFingerprints := range config.CertificateZones {
		matched, err := regexp.Match(zone, []byte(URL.Path))
		if !matched || err != nil {
			continue
		}
		authorised = false
		for _, clientCert := range clientCerts {
			for _, allowedFingerprint := range allowedFingerprints {
				if getCertFingerprint(clientCert) == allowedFingerprint {
					authorised = true
					break
				}
			}
		}
	}
	if !authorised {
		if len(clientCerts) > 0 {
			conn.Write([]byte("61 Provided certificate not authorised for this resource\r\n"))
			log.Status = 61
		} else {
			conn.Write([]byte("60 A pre-authorised certificate is required to access this resource\r\n"))
			log.Status = 60
		}
		return
	}
}

func getCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	return fingerprint
}
