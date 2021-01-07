package gemini

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
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
	Certificates CertificateDir

	// CreateCertificate, if not nil, will be called to create a new certificate
	// if the current one is expired or missing.
	CreateCertificate func(hostname string) (tls.Certificate, error)

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

// Register registers a responder for the given pattern.
//
// Patterns must be in the form of "hostname" or "scheme://hostname".
// If no scheme is specified, a scheme of "gemini://" is implied.
// Wildcard patterns are supported (e.g. "*.example.com").
func (s *Server) Register(pattern string, responder Responder) {
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

// RegisterFunc registers a responder function for the given pattern.
func (s *Server) RegisterFunc(pattern string, responder func(*ResponseWriter, *Request)) {
	s.Register(pattern, ResponderFunc(responder))
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

func (s *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := s.getCertificateFor(h.ServerName)
	if err != nil {
		// Try wildcard
		wildcard := strings.SplitN(h.ServerName, ".", 2)
		if len(wildcard) == 2 {
			cert, err = s.getCertificateFor("*." + wildcard[1])
		}
	}
	return cert, err
}

func (s *Server) getCertificateFor(hostname string) (*tls.Certificate, error) {
	if _, ok := s.hosts[hostname]; !ok {
		return nil, errors.New("hostname not registered")
	}

	// Generate a new certificate if it is missing or expired
	cert, ok := s.Certificates.Lookup(hostname)
	if !ok || cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()) {
		if s.CreateCertificate != nil {
			cert, err := s.CreateCertificate(hostname)
			if err == nil {
				s.Certificates.Add(hostname, cert)
				if err := s.Certificates.Write(hostname, cert); err != nil {
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
	return nil
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// ResponseWriter is used by a Gemini handler to construct a Gemini response.
type ResponseWriter struct {
	status      Status
	meta        string
	b           *bufio.Writer
	bodyAllowed bool
	wroteHeader bool
	mediatype   string
}

// NewResponseWriter returns a ResponseWriter that uses the provided io.Writer.
func NewResponseWriter(w io.Writer) *ResponseWriter {
	return &ResponseWriter{
		b: bufio.NewWriter(w),
	}
}

// Header sets the response header.
//
// Meta contains more information related to the response status.
// For successful responses, Meta should contain the mimetype of the response.
// For failure responses, Meta should contain a short description of the failure.
// Meta should not be longer than 1024 bytes.
func (w *ResponseWriter) Header(status Status, meta string) {
	w.status = status
	w.meta = meta
}

// Status sets the response header to the given status code.
//
// Status is equivalent to Header(status, status.Message())
func (w *ResponseWriter) Status(status Status) {
	meta := status.Message()

	if status.Class() == StatusClassSuccess {
		meta = w.mediatype
	}

	w.Header(status, meta)
}

// SetMediaType sets the media type that will be written for a successful response.
// If the mimetype is not set, it will default to "text/gemini".
func (w *ResponseWriter) SetMediaType(mediatype string) {
	w.mediatype = mediatype
}

// Write writes data to the connection as part of the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
//
// If the response header has not yet been written, Write calls WriteHeader
// with StatusSuccess and the mimetype set in SetMimetype.
func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		err := w.writeHeader()
		if err != nil {
			return 0, err
		}
	}

	if !w.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}

	return w.b.Write(b)
}

func (w *ResponseWriter) writeHeader() error {
	status := w.status
	if status == 0 {
		status = StatusSuccess
	}

	meta := w.meta

	if status.Class() == StatusClassSuccess {
		w.bodyAllowed = true

		if meta == "" {
			meta = w.mediatype
		}

		if meta == "" {
			meta = "text/gemini"
		}
	}

	_, err := fmt.Fprintf(w.b, "%d %s\r\n", int(status), meta)
	if err != nil {
		return fmt.Errorf("failed to write response header: %w", err)
	}

	w.wroteHeader = true

	return nil
}

// Flush writes any buffered data to the underlying io.Writer.
func (w *ResponseWriter) Flush() error {
	if !w.wroteHeader {
		err := w.writeHeader()
		if err != nil {
			return err
		}
	}

	return w.b.Flush()
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
