// +build example

package main

import (
	"log"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	host := "localhost"

	crt, key, err := gemini.NewCertificate(host)
	if err != nil {
		log.Fatal(err)
	}

	if err := gemini.WriteCertificate(host, crt, key); err != nil {
		log.Fatal(err)
	}
}
