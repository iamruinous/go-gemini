// +build example

package main

import (
	"crypto/tls"
	"log"

	"git.sr.ht/~adnano/gmi"
)

func main() {
	// Load a TLS key pair.
	// To generate a TLS key pair, run:
	//
	//     go run -tags=example ../cert
	//
	cert, err := tls.LoadX509KeyPair("examples/server/localhost.crt", "examples/server/localhost.key")
	if err != nil {
		log.Fatal(err)
	}

	mux := &gmi.ServeMux{}
	mux.Handle("/", gmi.FileServer(gmi.Dir("/var/www")))

	server := gmi.Server{
		Certificate: cert,
	}
	server.Handle("localhost", mux)
	server.ListenAndServe()
}
