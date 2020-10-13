// +build ignore

package main

import (
	"crypto/tls"
	"log"
	"time"

	"git.sr.ht/~adnano/gmi"
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
				log.Print("Old certificate expired, creating new one")
				// Generate a new certificate if the old one is expired.
				crt, key, err := gmi.NewRawCertificate(hostname, time.Minute)
				if err != nil {
					// Failed to generate new certificate, abort
					return nil
				}
				// Store and return the new certificate
				err = writeX509KeyPair("/var/lib/gemini/certs/"+hostname, crt, key)
				if err != nil {
					return nil
				}
				newCert, err := tls.X509KeyPair(crt, key)
				if err != nil {
					return nil
				}
				store.Add(hostname, newCert)
				return &newCert
			}
		}
		return cert
	}

	var mux gmi.ServeMux
	mux.Handle("/", gmi.FileServer(gmi.Dir("/var/www")))

	server.Handle("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// writeX509KeyPair writes the provided certificate and private key
// to path.crt and path.key respectively.
func writeX509KeyPair(path string, crt, key []byte) error {
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
