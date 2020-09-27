// +build example

package main

import (
	"crypto/tls"
	"log"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	// Load a TLS key pair.
	// To generate a TLS key pair, run:
	//
	//     go run -tags=example ../cert
	cert, err := tls.LoadX509KeyPair("examples/server/localhost.crt", "examples/server/localhost.key")
	if err != nil {
		log.Fatal(err)
	}

	mux := &gemini.ServeMux{}
	mux.Handle("/", gemini.FileServer(gemini.Dir("/var/www")))

	server := gemini.Server{
		Handler:     mux,
		Certificate: cert,
	}
	server.ListenAndServe()
}
