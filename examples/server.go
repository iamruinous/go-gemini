// +build ignore

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"

	gmi "git.sr.ht/~adnano/go-gemini"
)

func main() {
	var server gmi.Server
	if err := server.CertificateStore.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.GetCertificate = func(hostname string, store *gmi.CertificateStore) *tls.Certificate {
		cert, err := store.Lookup(hostname)
		if err != nil {
			switch err {
			case gmi.ErrCertificateExpired:
				// Generate a new certificate if the current one is expired.
				log.Print("Old certificate expired, creating new one")
				fallthrough
			case gmi.ErrCertificateUnknown:
				// Generate a certificate if one does not exist.
				cert, err := gmi.CreateCertificate(gmi.CertificateOptions{
					DNSNames: []string{hostname},
					Duration: time.Hour,
				})
				if err != nil {
					// Failed to generate new certificate, abort
					return nil
				}
				// Store and return the new certificate
				err = writeCertificate("/var/lib/gemini/certs/"+hostname, cert)
				if err != nil {
					return nil
				}
				store.Add(hostname, cert)
				return &cert
			}
		}
		return cert
	}

	var mux gmi.ServeMux
	mux.Handle("/", gmi.FileServer(gmi.Dir("/var/www")))

	server.Register("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// writeCertificate writes the provided certificate and private key
// to path.crt and path.key respectively.
func writeCertificate(path string, cert tls.Certificate) error {
	crt, err := marshalX509Certificate(cert.Leaf.Raw)
	if err != nil {
		return err
	}
	key, err := marshalPrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}

	// Write the certificate
	crtPath := path + ".crt"
	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := crtOut.Write(crt); err != nil {
		return err
	}

	// Write the private key
	keyPath := path + ".key"
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := keyOut.Write(key); err != nil {
		return err
	}
	return nil
}

// marshalX509Certificate returns a PEM-encoded version of the given raw certificate.
func marshalX509Certificate(cert []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// marshalPrivateKey returns PEM encoded versions of the given certificate and private key.
func marshalPrivateKey(priv interface{}) ([]byte, error) {
	var b bytes.Buffer
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
