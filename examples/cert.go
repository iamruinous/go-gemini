// +build ignore

package main

import (
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/gmi"
)

func main() {
	host := "localhost"
	duration := 365 * 24 * time.Hour
	crt, key, err := gmi.NewRawCertificate(host, duration)
	if err != nil {
		log.Fatal(err)
	}

	if err := writeX509KeyPair(host, crt, key); err != nil {
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
