// +build ignore

package main

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

type User struct {
	Name string
}

var (
	// Map of certificate hashes to users
	users = map[string]*User{}
)

func main() {
	certificates := &certificate.Store{}
	certificates.Register("localhost")
	if err := certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}

	mux := &gemini.ServeMux{}
	mux.HandleFunc("/", profile)
	mux.HandleFunc("/username", changeUsername)

	server := &gemini.Server{
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.GetCertificate,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func fingerprint(cert *x509.Certificate) string {
	b := sha512.Sum512(cert.Raw)
	return string(b[:])
}

func profile(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(gemini.StatusCertificateRequired, "Certificate required")
		return
	}
	fingerprint := fingerprint(r.TLS.PeerCertificates[0])
	user, ok := users[fingerprint]
	if !ok {
		user = &User{}
		users[fingerprint] = user
	}
	fmt.Fprintln(w, "Username:", user.Name)
	fmt.Fprintln(w, "=> /username Change username")
}

func changeUsername(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
	if len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(gemini.StatusCertificateRequired, "Certificate required")
		return
	}

	username, err := gemini.QueryUnescape(r.URL.RawQuery)
	if err != nil || username == "" {
		w.WriteHeader(gemini.StatusInput, "Username")
		return
	}
	fingerprint := fingerprint(r.TLS.PeerCertificates[0])
	user, ok := users[fingerprint]
	if !ok {
		user = &User{}
		users[fingerprint] = user
	}
	user.Name = username
	w.WriteHeader(gemini.StatusRedirect, "/")
}
