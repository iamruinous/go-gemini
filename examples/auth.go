// +build ignore

package main

import (
	"crypto/x509"
	"fmt"
	"log"

	gmi "git.sr.ht/~adnano/go-gemini"
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
	var mux gmi.ServeMux
	mux.HandleFunc("/", welcome)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/login/password", loginPassword)
	mux.HandleFunc("/profile", profile)
	mux.HandleFunc("/admin", admin)
	mux.HandleFunc("/logout", logout)

	var server gmi.Server
	if err := server.CertificateStore.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.Register("localhost", &mux)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func getSession(crt *x509.Certificate) (*session, bool) {
	fingerprint := gmi.Fingerprint(crt)
	session, ok := sessions[fingerprint]
	return session, ok
}

func welcome(w *gmi.ResponseWriter, r *gmi.Request) {
	fmt.Fprintln(w, "Welcome to this example.")
	fmt.Fprintln(w, "=> /login Login")
}

func login(w *gmi.ResponseWriter, r *gmi.Request) {
	cert, ok := gmi.Certificate(w, r)
	if !ok {
		return
	}
	username, ok := gmi.Input(w, r, "Username")
	if !ok {
		return
	}
	fingerprint := gmi.Fingerprint(cert)
	sessions[fingerprint] = &session{
		username: username,
	}
	gmi.Redirect(w, r, "/login/password")
}

func loginPassword(w *gmi.ResponseWriter, r *gmi.Request) {
	cert, ok := gmi.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
	if !ok {
		gmi.CertificateNotAuthorized(w, r)
		return
	}

	password, ok := gmi.SensitiveInput(w, r, "Password")
	if !ok {
		return
	}
	expected := logins[session.username].password
	if password == expected {
		session.authorized = true
		gmi.Redirect(w, r, "/profile")
	} else {
		gmi.SensitiveInput(w, r, "Wrong password. Try again")
	}
}

func logout(w *gmi.ResponseWriter, r *gmi.Request) {
	cert, ok := gmi.Certificate(w, r)
	if !ok {
		return
	}
	fingerprint := gmi.Fingerprint(cert)
	delete(sessions, fingerprint)
	fmt.Fprintln(w, "Successfully logged out.")
}

func profile(w *gmi.ResponseWriter, r *gmi.Request) {
	cert, ok := gmi.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
	if !ok {
		gmi.CertificateNotAuthorized(w, r)
		return
	}
	user := logins[session.username]
	fmt.Fprintln(w, "Username:", session.username)
	fmt.Fprintln(w, "Admin:", user.admin)
	fmt.Fprintln(w, "=> /logout Logout")
}

func admin(w *gmi.ResponseWriter, r *gmi.Request) {
	cert, ok := gmi.Certificate(w, r)
	if !ok {
		return
	}
	session, ok := getSession(cert)
	if !ok {
		gmi.CertificateNotAuthorized(w, r)
		return
	}
	user := logins[session.username]
	if !user.admin {
		gmi.CertificateNotAuthorized(w, r)
		return
	}
	fmt.Fprintln(w, "Welcome to the admin portal.")
}
