// +build ignore

package main

import (
	"log"

	"git.sr.ht/~adnano/gmi"
)

func main() {
	var server gmi.Server
	if err := server.CertificateStore.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}

	var mux gmi.ServeMux
	mux.Handle("/", gmi.FileServer(gmi.Dir("/var/www")))

	server.Handle("localhost", &mux)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
