// +build ignore

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	var server gemini.Server
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.CreateCertificate = func(hostname string) (tls.Certificate, error) {
		fmt.Println("Generating certificate for", hostname)
		cert, err := gemini.CreateCertificate(gemini.CertificateOptions{
			DNSNames: []string{hostname},
			Duration: time.Minute, // for testing purposes
		})
		if err == nil {
			// Write the new certificate to disk
			err = writeCertificate("/var/lib/gemini/certs/"+hostname, cert)
		}
		return cert, err
	}

	var mux gemini.ServeMux
	mux.Handle("/", gemini.FileServer(gemini.Dir("/var/www")))

	server.Register("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// writeCertificate writes the provided certificate and private key
// to path.crt and path.key respectively.
func writeCertificate(path string, cert tls.Certificate) error {
	// Write the certificate
	crtPath := path + ".crt"
	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := marshalX509Certificate(crtOut, cert.Leaf.Raw); err != nil {
		return err
	}

	// Write the private key
	keyPath := path + ".key"
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	return marshalPrivateKey(keyOut, cert.PrivateKey)
}

// marshalX509Certificate writes a PEM-encoded version of the given certificate.
func marshalX509Certificate(w io.Writer, cert []byte) error {
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
}

// marshalPrivateKey writes a PEM-encoded version of the given private key.
func marshalPrivateKey(w io.Writer, priv crypto.PrivateKey) error {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}
