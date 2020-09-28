// +build example

package main

import (
	"crypto/tls"
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
		Handler:     handler,
	}

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
	if len(req.TLS.PeerCertificates) > 0 {
		if username := req.URL.RawQuery; username == "" {
			gmi.Input(rw, req, "Username")
		} else {
			fingerprint := gmi.Fingerprint(req.TLS.PeerCertificates[0])
			sessions[fingerprint] = &session{
				username: username,
			}
			gmi.Redirect(rw, req, "/login/password", false)
		}
	} else {
		gmi.CertificateRequired(rw, req)
	}
}

func loginPassword(rw *gmi.ResponseWriter, req *gmi.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
		if !ok {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}

		if password := req.URL.RawQuery; password == "" {
			gmi.SensitiveInput(rw, req, "Password")
		} else {
			expected := logins[session.username].password
			if password == expected {
				session.authorized = true
				gmi.Redirect(rw, req, "/profile", false)
			} else {
				gmi.SensitiveInput(rw, req, "Wrong password. Try again")
			}
		}
	} else {
		gmi.CertificateRequired(rw, req)
	}
}

func logout(rw *gmi.ResponseWriter, req *gmi.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		fingerprint := gmi.Fingerprint(req.TLS.PeerCertificates[0])
		delete(sessions, fingerprint)
	}
	rw.Write([]byte("Successfully logged out.\n"))
}

func profile(rw *gmi.ResponseWriter, req *gmi.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
		if !ok {
			gmi.CertificateNotAuthorized(rw, req)
			return
		}
		user := logins[session.username]
		profile := fmt.Sprintf("Username: %s\nAdmin: %t\n=> /logout Logout", session.username, user.admin)
		rw.Write([]byte(profile))
	} else {
		gmi.CertificateRequired(rw, req)
	}
}

func admin(rw *gmi.ResponseWriter, req *gmi.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
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
	} else {
		gmi.CertificateRequired(rw, req)
	}
}
