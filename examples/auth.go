// +build ignore

package main

import (
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

type User struct {
	Name string
}

var (
	// Map of certificate hashes to users
	users = map[string]*User{}
)

func main() {
	var mux gemini.ServeMux
	mux.HandleFunc("/", profile)
	mux.HandleFunc("/username", changeUsername)
	mux.HandleFunc("/delete", deleteAccount)

	var server gemini.Server
	if err := server.Certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.CreateCertificate = func(hostname string) (tls.Certificate, error) {
		return gemini.CreateCertificate(gemini.CertificateOptions{
			Subject: pkix.Name{
				CommonName: hostname,
			},
			DNSNames: []string{hostname},
			Duration: time.Hour,
		})
	}
	server.Register("localhost", &mux)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func fingerprint(cert *x509.Certificate) string {
	b := sha512.Sum512(cert.Raw)
	return string(b[:])
}

func profile(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	fingerprint := fingerprint(r.Certificate.Leaf)
	user, ok := users[fingerprint]
	if !ok {
		user = &User{}
		users[fingerprint] = user
	}
	fmt.Fprintln(w, "Username:", user.Name)
	fmt.Fprintln(w, "=> /username Change username")
	fmt.Fprintln(w, "=> /delete Delete account")
}

func changeUsername(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}

	username, ok := gemini.Input(r)
	if !ok {
		w.WriteHeader(gemini.StatusInput, "Username")
		return
	}
	users[fingerprint(r.Certificate.Leaf)].Name = username
	fmt.Fprintln(w, "Successfully changed username")
}

func deleteAccount(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate != nil {
		delete(users, fingerprint(r.Certificate.Leaf))
	}
	fmt.Fprintln(w, "Account deleted")
}
