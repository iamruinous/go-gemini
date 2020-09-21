// +build example

package main

import (
	"crypto/tls"
	"git.sr.ht/~adnano/go-gemini"
	"log"
	"net/url"
)

func main() {
	// Load a TLS key pair.
	// To generate a TLS key pair, run:
	//
	//     openssl genrsa -out server.key 2048
	//     openssl ecparam -genkey -name secp384r1 -out server.key
	//     openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
	//
	config := &tls.Config{}
	cert, err := tls.LoadX509KeyPair("example/server/server.crt", "example/server/server.key")
	if err != nil {
		log.Fatal(err)
	}
	config.Certificates = append(config.Certificates, cert)

	mux := &gemini.Mux{}
	mux.HandleFunc("/", func(url *url.URL) *gemini.Response {
		return &gemini.Response{
			Status: gemini.StatusSuccess,
			Meta:   "text/gemini",
			Body:   []byte("You requested " + url.String()),
		}
	})

	server := gemini.Server{
		TLSConfig: config,
		Handler:   mux,
	}
	server.ListenAndServe()
}
