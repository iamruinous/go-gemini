package gemini

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"git.sr.ht/~adnano/go-gemini/certificate"
)

// Server is a Gemini server.
type Server struct {
	// Addr specifies the address that the server should listen on.
	// If Addr is empty, the server will listen on the address ":1965".
	Addr string

	// ReadTimeout is the maximum duration for reading a request.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response.
	WriteTimeout time.Duration

	// Certificates contains the certificates used by the server.
	Certificates certificate.Dir

	// GetCertificate, if not nil, will be called to retrieve a new certificate
	// if the current one is expired or missing.
	GetCertificate func(hostname string) (tls.Certificate, error)

	// ErrorLog specifies an optional logger for errors accepting connections
	// and file system errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	// registered responders
	responders map[responderKey]Responder
	hosts      map[string]bool
}

type responderKey struct {
	scheme   string
	hostname string
}

// Handle registers a responder for the given pattern.
//
// The pattern must be in the form of "hostname" or "scheme://hostname".
// If no scheme is specified, a scheme of "gemini://" is implied.
// Wildcard patterns are supported (e.g. "*.example.com").
// To handle any hostname, use the wildcard pattern "*".
func (s *Server) Handle(pattern string, responder Responder) {
	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if responder == nil {
		panic("gemini: nil responder")
	}
	if s.responders == nil {
		s.responders = map[responderKey]Responder{}
		s.hosts = map[string]bool{}
	}

	split := strings.SplitN(pattern, "://", 2)
	var key responderKey
	if len(split) == 2 {
		key.scheme = split[0]
		key.hostname = split[1]
	} else {
		key.scheme = "gemini"
		key.hostname = split[0]
	}

	if _, ok := s.responders[key]; ok {
		panic("gemini: multiple registrations for " + pattern)
	}
	s.responders[key] = responder
	s.hosts[key.hostname] = true
}

// HandleFunc registers a responder function for the given pattern.
func (s *Server) HandleFunc(pattern string, responder func(*ResponseWriter, *Request)) {
	s.Handle(pattern, ResponderFunc(responder))
}

// ListenAndServe listens for requests at the server's configured address.
func (s *Server) ListenAndServe() error {
	addr := s.Addr
	if addr == "" {
		addr = ":1965"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	return s.Serve(tls.NewListener(ln, &tls.Config{
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.getCertificate,
	}))
}

// Serve listens for requests on the provided listener.
func (s *Server) Serve(l net.Listener) error {
	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		rw, err := l.Accept()
		if err != nil {
			// If this is a temporary error, sleep
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.logf("gemini: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			// Otherwise, return the error
			return err
		}

		tempDelay = 0
		go s.respond(rw)
	}
}

// getCertificate retrieves a certificate for the given client hello.
func (s *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := s.lookupCertificate(h.ServerName, h.ServerName)
	if err != nil {
		// Try wildcard
		wildcard := strings.SplitN(h.ServerName, ".", 2)
		if len(wildcard) == 2 {
			// Use the wildcard pattern as the hostname.
			hostname := "*." + wildcard[1]
			cert, err = s.lookupCertificate(hostname, hostname)
		}
		// Try "*" wildcard
		if err != nil {
			// Use the server name as the hostname
			// since "*" is not a valid hostname.
			cert, err = s.lookupCertificate("*", h.ServerName)
		}
	}
	return cert, err
}

// lookupCertificate retrieves the certificate for the given hostname,
// if and only if the provided pattern is registered.
// If no certificate is found in the certificate store or the certificate
// is expired, it calls GetCertificate to retrieve a new certificate.
func (s *Server) lookupCertificate(pattern, hostname string) (*tls.Certificate, error) {
	if _, ok := s.hosts[pattern]; !ok {
		return nil, errors.New("hostname not registered")
	}

	cert, ok := s.Certificates.Lookup(hostname)
	if !ok || cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()) {
		if s.GetCertificate != nil {
			cert, err := s.GetCertificate(hostname)
			if err == nil {
				if err := s.Certificates.Add(hostname, cert); err != nil {
					s.logf("gemini: Failed to write new certificate for %s: %s", hostname, err)
				}
			}
			return &cert, err
		}
		return nil, errors.New("no certificate")
	}

	return &cert, nil
}

// respond responds to a connection.
func (s *Server) respond(conn net.Conn) {
	defer conn.Close()
	if d := s.ReadTimeout; d != 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := s.WriteTimeout; d != 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(d))
	}

	w := NewResponseWriter(conn)
	defer func() {
		_ = w.Flush()
	}()

	req, err := ReadRequest(conn)
	if err != nil {
		w.Status(StatusBadRequest)
		return
	}

	// Store information about the TLS connection
	if tlsConn, ok := conn.(*tls.Conn); ok {
		req.TLS = tlsConn.ConnectionState()
		if len(req.TLS.PeerCertificates) > 0 {
			peerCert := req.TLS.PeerCertificates[0]
			// Store the TLS certificate
			req.Certificate = &tls.Certificate{
				Certificate: [][]byte{peerCert.Raw},
				Leaf:        peerCert,
			}
		}
	}

	resp := s.responder(req)
	if resp == nil {
		w.Status(StatusNotFound)
		return
	}

	resp.Respond(w, req)
}

func (s *Server) responder(r *Request) Responder {
	if h, ok := s.responders[responderKey{r.URL.Scheme, r.URL.Hostname()}]; ok {
		return h
	}
	wildcard := strings.SplitN(r.URL.Hostname(), ".", 2)
	if len(wildcard) == 2 {
		if h, ok := s.responders[responderKey{r.URL.Scheme, "*." + wildcard[1]}]; ok {
			return h
		}
	}
	if h, ok := s.responders[responderKey{r.URL.Scheme, "*"}]; ok {
		return h
	}
	return nil
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// A Responder responds to a Gemini request.
type Responder interface {
	// Respond accepts a Request and constructs a Response.
	Respond(*ResponseWriter, *Request)
}

// ResponderFunc is a wrapper around a bare function that implements Responder.
type ResponderFunc func(*ResponseWriter, *Request)

func (f ResponderFunc) Respond(w *ResponseWriter, r *Request) {
	f(w, r)
}
