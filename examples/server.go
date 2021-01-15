// +build ignore

// This example illustrates a Gemini server.

package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	var server gemini.Server
	server.ReadTimeout = 30 * time.Second
	server.WriteTimeout = 1 * time.Minute
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.CreateCertificate = func(hostname string) (tls.Certificate, error) {
		return certificate.Create(certificate.CreateOptions{
			Subject: pkix.Name{
				CommonName: hostname,
			},
			DNSNames: []string{hostname},
			Duration: 365 * 24 * time.Hour,
		})
	}

	var mux gemini.ServeMux
	mux.Handle("/", gemini.FileServer(gemini.Dir("/var/www")))

	server.Handle("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
