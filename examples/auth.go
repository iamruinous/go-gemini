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
	var mux gemini.ServeMux
	mux.HandleFunc("/", profile)
	mux.HandleFunc("/username", changeUsername)

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
			Duration: time.Hour,
		})
	}
	server.Handler = &mux

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func fingerprint(cert *x509.Certificate) string {
	b := sha512.Sum512(cert.Raw)
	return string(b[:])
}

func profile(w gemini.ResponseWriter, r *gemini.Request) {
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

func changeUsername(w gemini.ResponseWriter, r *gemini.Request) {
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
