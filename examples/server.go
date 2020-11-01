// +build ignore

package main

import (
	"crypto/tls"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	var server gemini.Server
	server.ReadTimeout = 1 * time.Minute
	server.WriteTimeout = 2 * time.Minute
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.CreateCertificate = func(hostname string) (tls.Certificate, error) {
		return gemini.CreateCertificate(gemini.CertificateOptions{
			DNSNames: []string{hostname},
			Duration: time.Minute, // for testing purposes
		})
	}

	var mux gemini.ServeMux
	mux.Handle("/", gemini.FileServer(gemini.Dir("/var/www")))

	server.Register("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
