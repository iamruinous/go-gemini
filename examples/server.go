// +build ignore

// This example illustrates a Gemini server.

package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	certificates := &certificate.Store{
		CreateCertificate: func(hostname string) (tls.Certificate, error) {
			return certificate.Create(certificate.CreateOptions{
				Subject: pkix.Name{
					CommonName: hostname,
				},
				DNSNames: []string{hostname},
				Duration: 365 * 24 * time.Hour,
			})
		},
	}
	certificates.Register("localhost")
	if err := certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}

	mux := &gemini.ServeMux{}
	mux.Handle("/", gemini.FileServer(os.DirFS("/var/www")))

	server := &gemini.Server{
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.GetCertificate,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
