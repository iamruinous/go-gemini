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
	cert, err := tls.LoadX509KeyPair("examples/client/localhost.crt", "examples/client/localhost.key")
	if err != nil {
		log.Fatal(err)
	}

	handler := &gemini.ServeMux{}
	handler.HandleFunc("", welcome)
	handler.HandleFunc("/login", login)
	handler.HandleFunc("/login/password", loginPassword)
	handler.HandleFunc("/profile", profile)
	handler.HandleFunc("/admin", admin)
	handler.HandleFunc("/logout", logout)

	server := &gemini.Server{
		Certificate: cert,
		Handler:     handler,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func getSession(crt *x509.Certificate) (*session, bool) {
	fingerprint := gemini.Fingerprint(crt)
	session, ok := sessions[fingerprint]
	return session, ok
}

func welcome(rw *gemini.ResponseWriter, req *gemini.Request) {
	rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
	rw.Write([]byte("Welcome to this example.\n=> /login Login\n"))
}

func login(rw *gemini.ResponseWriter, req *gemini.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		if username := req.URL.RawQuery; username == "" {
			rw.WriteHeader(gemini.StatusInput, "Username")
		} else {
			fingerprint := gemini.Fingerprint(req.TLS.PeerCertificates[0])
			sessions[fingerprint] = &session{
				username: username,
			}
			// TODO: Remove scheme and host once example client can handle relative redirects
			rw.WriteHeader(gemini.StatusRedirectTemporary, "gemini://localhost/login/password")
		}
	} else {
		rw.WriteHeader(gemini.StatusClientCertificateRequired, "Certificate required")
	}
}

func loginPassword(rw *gemini.ResponseWriter, req *gemini.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
		if !ok {
			rw.WriteHeader(gemini.StatusCertificateNotAuthorised, "Not authorized")
			return
		}

		if password := req.URL.RawQuery; password == "" {
			rw.WriteHeader(gemini.StatusInput, "Password")
		} else {
			expected := logins[session.username].password
			if password == expected {
				// TODO: Remove scheme and host once example client can handle relative redirects
				session.authorized = true
				rw.WriteHeader(gemini.StatusRedirectTemporary, "gemini://localhost/profile")
			} else {
				rw.WriteHeader(gemini.StatusInput, "Wrong password. Please try again.\nPassword:")
			}
		}
	} else {
		rw.WriteHeader(gemini.StatusClientCertificateRequired, "Certificate required")
	}
}

func logout(rw *gemini.ResponseWriter, req *gemini.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		fingerprint := gemini.Fingerprint(req.TLS.PeerCertificates[0])
		delete(sessions, fingerprint)
	}
	rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
	rw.Write([]byte("Successfully logged out.\n"))
}

func profile(rw *gemini.ResponseWriter, req *gemini.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
		if !ok {
			rw.WriteHeader(gemini.StatusCertificateNotAuthorised, "Certificate not authorized")
			return
		}
		user := logins[session.username]
		profile := fmt.Sprintf("Username: %s\nAdmin: %t\n=> /logout Logout", session.username, user.admin)
		rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
		rw.Write([]byte(profile))
	} else {
		rw.WriteHeader(gemini.StatusClientCertificateRequired, "Certificate required")
	}
}

func admin(rw *gemini.ResponseWriter, req *gemini.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		session, ok := getSession(req.TLS.PeerCertificates[0])
		if !ok {
			rw.WriteHeader(gemini.StatusCertificateNotAuthorised, "Certificate not authorized")
			return
		}
		user := logins[session.username]
		if !user.admin {
			rw.WriteHeader(gemini.StatusCertificateNotAuthorised, "Admins only!")
			return
		}
		rw.WriteHeader(gemini.StatusSuccess, "text/gemini")
		rw.Write([]byte("Welcome to the admin portal.\n"))
	} else {
		rw.WriteHeader(gemini.StatusClientCertificateRequired, "Certificate required")
	}
}
