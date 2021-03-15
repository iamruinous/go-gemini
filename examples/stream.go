// +build ignore

// This example illustrates a streaming Gemini server.

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	certificates := &certificate.Store{}
	certificates.Register("localhost")
	if err := certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}

	mux := &gemini.Mux{}
	mux.HandleFunc("/", stream)

	server := &gemini.Server{
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.Get,
	}

	ctx := context.Background()
	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatal(err)
	}
}

// stream writes an infinite stream to w.
func stream(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		fmt.Fprintln(w, time.Now().UTC())
		if err := w.Flush(); err != nil {
			return
		}
		time.Sleep(time.Second)
	}
}
