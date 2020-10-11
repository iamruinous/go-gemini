// +build example

package main

import (
	"crypto/tls"
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
	// Configure a certificate.
	// To generate a TLS key pair, run:
	//
	//     go run -tags=example ../cert
	//
	cert, err := tls.LoadX509KeyPair("examples/server/localhost.crt", "examples/server/localhost.key")
	if err != nil {
		log.Fatal(err)
	}

	handler := &gmi.ServeMux{}
	handler.HandleFunc("/", welcome)
	handler.HandleFunc("/login", login)
	handler.HandleFunc("/login/password", loginPassword)
	handler.HandleFunc("/profile", profile)
	handler.HandleFunc("/admin", admin)
	handler.HandleFunc("/logout", logout)

	server := &gmi.Server{
		Certificate: cert,
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

func welcome(rw *gmi.ResponseWriter, req *gmi.Request) {
	rw.Write([]byte("Welcome to this example.\n=> /login Login\n"))
}

func login(rw *gmi.ResponseWriter, req *gmi.Request) {
	gmi.WithCertificate(rw, req, func(cert *x509.Certificate) {
		gmi.WithInput(rw, req, "Username", func(username string) {
			fingerprint := gmi.Fingerprint(cert)
			sessions[fingerprint] = &session{
				username: username,
			}
			gmi.Redirect(rw, req, "/login/password")
		})
	})
}

func loginPassword(rw *gmi.ResponseWriter, req *gmi.Request) {
	gmi.WithCertificate(rw, req, func(cert *x509.Certificate) {
		session, ok := getSession(cert)
		if !ok {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}

		gmi.WithSensitiveInput(rw, req, "Password", func(password string) {
			expected := logins[session.username].password
			if password == expected {
				session.authorized = true
				gmi.Redirect(rw, req, "/profile")
			} else {
				gmi.SensitiveInput(rw, req, "Wrong password. Try again")
			}
		})
	})
}

func logout(rw *gmi.ResponseWriter, req *gmi.Request) {
	gmi.WithCertificate(rw, req, func(cert *x509.Certificate) {
		fingerprint := gmi.Fingerprint(cert)
		delete(sessions, fingerprint)
	})
	rw.Write([]byte("Successfully logged out.\n"))
}

func profile(rw *gmi.ResponseWriter, req *gmi.Request) {
	gmi.WithCertificate(rw, req, func(cert *x509.Certificate) {
		session, ok := getSession(cert)
		if !ok {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}
		user := logins[session.username]
		profile := fmt.Sprintf("Username: %s\nAdmin: %t\n=> /logout Logout", session.username, user.admin)
		rw.Write([]byte(profile))
	})
}

func admin(rw *gmi.ResponseWriter, req *gmi.Request) {
	gmi.WithCertificate(rw, req, func(cert *x509.Certificate) {
		session, ok := getSession(cert)
		if !ok {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}
		user := logins[session.username]
		if !user.admin {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}
		rw.Write([]byte("Welcome to the admin portal.\n"))
	})
}
