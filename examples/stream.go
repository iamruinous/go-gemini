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

	mux := &gemini.ServeMux{}
	mux.HandleFunc("/", stream)

	server := &gemini.Server{
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.GetCertificate,
	}

	ctx := context.Background()
	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatal(err)
	}
}

// stream writes an infinite stream to w.
func stream(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
	ch := make(chan string)
	ctx, cancel := context.WithCancel(ctx)

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				ch <- fmt.Sprint(time.Now().UTC())
			}
			time.Sleep(time.Second)
		}
		// Close channel when finished.
		// In this example this will never be reached.
		close(ch)
	}(ctx)

	for {
		s, ok := <-ch
		if !ok {
			break
		}
		fmt.Fprintln(w, s)
		if err := w.Flush(); err != nil {
			cancel()
			return
		}
	}
}
