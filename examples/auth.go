// +build ignore

package main

import (
	"crypto/x509"
	"fmt"
	"log"

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
	server.Register("localhost", &mux)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func getSession(crt *x509.Certificate) (*session, bool) {
	fingerprint := gemini.Fingerprint(crt)
	session, ok := sessions[fingerprint]
	return session, ok
}

func login(w *gemini.ResponseWriter, r *gemini.Request) {
	cert, ok := gemini.Certificate(w, r)
	if !ok {
		return
	}
	username, ok := gemini.Input(w, r, "Username")
	if !ok {
		return
	}
	fingerprint := gemini.Fingerprint(cert)
	sessions[fingerprint] = &session{
		username: username,
	}
	gemini.Redirect(w, "/password")
}

func loginPassword(w *gemini.ResponseWriter, r *gemini.Request) {
	cert, ok := gemini.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
	if !ok {
		w.WriteStatus(gemini.StatusCertificateNotAuthorized)
		return
	}

	password, ok := gemini.SensitiveInput(w, r, "Password")
	if !ok {
		return
	}
	expected := logins[session.username].password
	if password == expected {
		session.authorized = true
		gemini.Redirect(w, "/profile")
	} else {
		gemini.SensitiveInput(w, r, "Wrong password. Try again")
	}
}

func logout(w *gemini.ResponseWriter, r *gemini.Request) {
	cert, ok := gemini.Certificate(w, r)
	if !ok {
		return
	}
	fingerprint := gemini.Fingerprint(cert)
	delete(sessions, fingerprint)
	fmt.Fprintln(w, "Successfully logged out.")
}

func profile(w *gemini.ResponseWriter, r *gemini.Request) {
	cert, ok := gemini.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
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
	cert, ok := gemini.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
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
