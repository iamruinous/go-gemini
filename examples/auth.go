// +build ignore

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

type user struct {
	password string // TODO: use hashes
	admin    bool
}

type session struct {
	username   string
	authorized bool // whether or not the password was supplied
}

var (
	// Map of usernames to user data
	logins = map[string]user{
		"admin": {"p@ssw0rd", true}, // NOTE: These are bad passwords!
		"user1": {"password1", false},
		"user2": {"password2", false},
	}

	// Map of certificate fingerprints to sessions
	sessions = map[string]*session{}
)

func main() {
	var mux gemini.ServeMux
	mux.HandleFunc("/", login)
	mux.HandleFunc("/password", loginPassword)
	mux.HandleFunc("/profile", profile)
	mux.HandleFunc("/admin", admin)
	mux.HandleFunc("/logout", logout)

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

func getSession(cert *x509.Certificate) (*session, bool) {
	fingerprint := gemini.Fingerprint(cert)
	session, ok := sessions[fingerprint]
	return session, ok
}

func login(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	username, ok := gemini.Input(r)
	if !ok {
		w.WriteHeader(gemini.StatusInput, "Username")
		return
	}
	fingerprint := gemini.Fingerprint(r.Certificate.Leaf)
	sessions[fingerprint] = &session{
		username: username,
	}
	w.WriteHeader(gemini.StatusRedirect, "/password")
}

func loginPassword(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	session, ok := getSession(r.Certificate.Leaf)
	if !ok {
		w.WriteStatus(gemini.StatusCertificateNotAuthorized)
		return
	}

	password, ok := gemini.Input(r)
	if !ok {
		w.WriteHeader(gemini.StatusSensitiveInput, "Password")
		return
	}
	expected := logins[session.username].password
	if password == expected {
		session.authorized = true
		w.WriteHeader(gemini.StatusRedirect, "/profile")
	} else {
		w.WriteHeader(gemini.StatusSensitiveInput, "Password")
	}
}

func logout(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	fingerprint := gemini.Fingerprint(r.Certificate.Leaf)
	delete(sessions, fingerprint)
	fmt.Fprintln(w, "Successfully logged out.")
	fmt.Fprintln(w, "=> / Index")
}

func profile(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	session, ok := getSession(r.Certificate.Leaf)
	if !ok {
		w.WriteStatus(gemini.StatusCertificateNotAuthorized)
		return
	}
	user := logins[session.username]
	fmt.Fprintln(w, "Username:", session.username)
	fmt.Fprintln(w, "Admin:", user.admin)
	fmt.Fprintln(w, "=> /logout Logout")
}

func admin(w *gemini.ResponseWriter, r *gemini.Request) {
	if r.Certificate == nil {
		w.WriteStatus(gemini.StatusCertificateRequired)
		return
	}
	session, ok := getSession(r.Certificate.Leaf)
	if !ok {
		w.WriteStatus(gemini.StatusCertificateNotAuthorized)
		return
	}
	user := logins[session.username]
	if !user.admin {
		w.WriteStatus(gemini.StatusCertificateNotAuthorized)
		return
	}
	fmt.Fprintln(w, "Welcome to the admin portal.")
}
