// +build ignore

package main

import (
	"log"
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

	if err := gmi.WriteX509KeyPair(host, crt, key); err != nil {
		log.Fatal(err)
	}
}
