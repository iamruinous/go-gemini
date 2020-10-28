// +build ignore

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("usage: %s [hostname] [duration]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	duration, err := time.ParseDuration(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	options := gemini.CertificateOptions{
		DNSNames: []string{host},
		Duration: duration,
	}
	cert, err := gemini.CreateCertificate(options)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeCertificate(host, cert); err != nil {
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
