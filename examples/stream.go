// +build ignore

// This example illustrates a streaming Gemini server.

package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	var server gemini.Server
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.CreateCertificate = func(hostname string) (tls.Certificate, error) {
		return gemini.CreateCertificate(gemini.CertificateOptions{
			Subject: pkix.Name{
				CommonName: hostname,
			},
			DNSNames: []string{hostname},
			Duration: 365 * 24 * time.Hour,
		})
	}

	server.RegisterFunc("localhost", stream)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func stream(w *gemini.ResponseWriter, r *gemini.Request) {
	for {
		fmt.Fprintln(w, time.Now())
		time.Sleep(time.Second)
	}
}
