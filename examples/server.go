// +build ignore

// This example illustrates a Gemini server.

package main

import (
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	certificates := &certificate.Store{}
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
