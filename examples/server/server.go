// +build example

package main

import (
	"log"

	"git.sr.ht/~adnano/gmi"
)

func main() {
	mux := &gmi.ServeMux{}
	mux.Handle("/", gmi.FileServer(gmi.Dir("/var/www")))

	server := gmi.Server{}
	if err := server.CertificateStore.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	log.Print(server.CertificateStore)
	server.Handle("localhost", mux)
	server.ListenAndServe()
}
