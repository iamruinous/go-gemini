// +build ignore

// This example illustrates a certificate generation tool.

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("usage: %s [hostname] [duration]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	duration, err := time.ParseDuration(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	options := gemini.CertificateOptions{
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames: []string{host},
		Duration: duration,
	}
	cert, err := gemini.CreateCertificate(options)
	if err != nil {
		log.Fatal(err)
	}
	certPath := host + ".crt"
	keyPath := host + ".key"
	if err := gemini.WriteCertificate(cert, certPath, keyPath); err != nil {
		log.Fatal(err)
	}
}
