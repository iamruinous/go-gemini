// +build ignore

// This example illustrates a streaming Gemini server.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	var server gemini.Server
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.GetCertificate = func(hostname string) (tls.Certificate, error) {
		return certificate.Create(certificate.CreateOptions{
			Subject: pkix.Name{
				CommonName: hostname,
			},
			DNSNames: []string{hostname},
			Duration: 365 * 24 * time.Hour,
		})
	}

	server.HandleFunc("localhost", stream)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// stream writes an infinite stream to w.
func stream(w gemini.ResponseWriter, r *gemini.Request) {
	ch := make(chan string)
	ctx, cancel := context.WithCancel(context.Background())

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
