// +build example

package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	// Load a TLS key pair.
	// To generate a TLS key pair, run:
	//
	//     openssl genrsa -out server.key 2048
	//     openssl ecparam -genkey -name secp384r1 -out server.key
	//     openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
	//
	config := tls.Config{}
	cert, err := tls.LoadX509KeyPair("examples/server/server.crt", "examples/server/server.key")
	if err != nil {
		log.Fatal(err)
	}
	config.Certificates = append(config.Certificates, cert)
	config.ClientAuth = tls.RequestClientCert
	config.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		return nil
	}

	mux := &gemini.ServeMux{}
	// mux.HandleFunc("/", func(rw *gemini.ResponseWriter, req *gemini.Request) {
	// 	log.Printf("Request from %s for %s with certificates %v", req.RemoteAddr.String(), req.URL.String(), req.TLS.PeerCertificates)
	// 	rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
	// 	rw.Write([]byte("You requested " + req.URL.String()))
	// })
	// mux.HandleFunc("/cert", func(rw *gemini.ResponseWriter, req *gemini.Request) {
	// 	rw.WriteHeader(gemini.StatusClientCertificateRequired, "Certificate required")
	// })

	mux.HandleFunc("https://example.com/path", nil)
	mux.HandleFunc("http://example.com/path", nil)
	mux.HandleFunc("example.com/path", nil)
	mux.HandleFunc("/path", nil)
	mux.HandleFunc("/longpath", nil)

	server := gemini.Server{
		TLSConfig: config,
		Handler:   mux,
	}
	server.ListenAndServe()
}
