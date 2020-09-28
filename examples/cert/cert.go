// +build example

package main

import (
	"log"
	"time"

	gmi "git.sr.ht/~adnano/go-gemini"
)

func main() {
	host := "localhost"

	duration := 365 * 24 * time.Hour
	crt, key, err := gmi.NewRawCertificate(host, duration)
	if err != nil {
		log.Fatal(err)
	}

	if err := gmi.WriteCertificate(host, crt, key); err != nil {
		log.Fatal(err)
	}
}
