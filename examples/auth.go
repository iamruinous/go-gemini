// +build ignore

package main

import (
	"crypto/x509"
	"fmt"
	"log"

	"git.sr.ht/~adnano/gmi"
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
	handler := &gmi.ServeMux{}
	handler.HandleFunc("/", welcome)
	handler.HandleFunc("/login", login)
	handler.HandleFunc("/login/password", loginPassword)
	handler.HandleFunc("/profile", profile)
	handler.HandleFunc("/admin", admin)
	handler.HandleFunc("/logout", logout)

	server := &gmi.Server{}
	if err := server.CertificateStore.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}
	server.Handle("localhost", handler)

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
	w.Write([]byte("Welcome to this example.\n=> /login Login\n"))
}

func login(w *gmi.ResponseWriter, r *gmi.Request) {
	gmi.WithCertificate(w, r, func(cert *x509.Certificate) {
		gmi.WithInput(w, r, "Username", func(username string) {
			fingerprint := gmi.Fingerprint(cert)
			sessions[fingerprint] = &session{
				username: username,
			}
			gmi.Redirect(w, r, "/login/password")
		})
	})
}

func loginPassword(w *gmi.ResponseWriter, r *gmi.Request) {
	gmi.WithCertificate(w, r, func(cert *x509.Certificate) {
		session, ok := getSession(cert)
		if !ok {
			gmi.CertificateNotAuthorized(w, r)
			return
		}

		gmi.WithSensitiveInput(w, r, "Password", func(password string) {
			expected := logins[session.username].password
			if password == expected {
				session.authorized = true
				gmi.Redirect(w, r, "/profile")
			} else {
				gmi.SensitiveInput(w, r, "Wrong password. Try again")
			}
		})
	})
}

func logout(w *gmi.ResponseWriter, r *gmi.Request) {
	gmi.WithCertificate(w, r, func(cert *x509.Certificate) {
		fingerprint := gmi.Fingerprint(cert)
		delete(sessions, fingerprint)
	})
	w.Write([]byte("Successfully logged out.\n"))
}

func profile(w *gmi.ResponseWriter, r *gmi.Request) {
	gmi.WithCertificate(w, r, func(cert *x509.Certificate) {
		session, ok := getSession(cert)
		if !ok {
			gmi.CertificateNotAuthorized(w, r)
			return
		}
		user := logins[session.username]
		profile := fmt.Sprintf("Username: %s\nAdmin: %t\n=> /logout Logout", session.username, user.admin)
		w.Write([]byte(profile))
	})
}

func admin(w *gmi.ResponseWriter, r *gmi.Request) {
	gmi.WithCertificate(w, r, func(cert *x509.Certificate) {
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
		w.Write([]byte("Welcome to the admin portal.\n"))
	})
}
