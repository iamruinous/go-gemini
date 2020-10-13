// +build ignore

package main

import (
	"log"
	"time"

	"git.sr.ht/~adnano/gmi"
)

func main() {
	host := "localhost"

	duration := 2 * time.Minute
	crt, key, err := gmi.NewRawCertificate(host, duration)
	if err != nil {
		log.Fatal(err)
	}

	if err := gmi.WriteX509KeyPair(host, crt, key); err != nil {
		log.Fatal(err)
	}
}
