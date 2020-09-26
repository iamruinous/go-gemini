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
	//     openssl genrsa -out server.key 2048
	//     openssl ecparam -genkey -name secp384r1 -out server.key
	//     openssl req -new -x509 -sha512 -key server.key -out server.crt -days 365
	//
	cert, err := tls.LoadX509KeyPair("examples/server/server.crt", "examples/server/server.key")
	if err != nil {
		log.Fatal(err)
	}

	mux := &gemini.ServeMux{}
	mux.HandleFunc("/", func(rw *gemini.ResponseWriter, req *gemini.Request) {
		rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
		rw.Write([]byte("You requested " + req.URL.String()))
		log.Printf("Request from %s for %s", req.RemoteAddr.String(), req.URL)
	})

	server := gemini.Server{
		Handler:     mux,
		Certificate: cert,
	}
	server.ListenAndServe()
}
