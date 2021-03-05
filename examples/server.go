// +build ignore

// This example illustrates a Gemini server.

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
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
	mux.Handle("/", gemini.FileServer(os.DirFS("/var/www")))

	server := &gemini.Server{
		Handler:        gemini.LoggingMiddleware(mux),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.Get,
	}

	// Listen for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	errch := make(chan error)
	go func() {
		ctx := context.Background()
		errch <- server.ListenAndServe(ctx)
	}()

	select {
	case err := <-errch:
		log.Fatal(err)
	case <-c:
		// Shutdown the server
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Fatal(err)
		}
	}
}
