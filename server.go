package gemini

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/url"
	"strconv"
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
	Certificates CertificateStore

	// CreateCertificate, if not nil, will be called to create a new certificate
	// if the current one is expired or missing.
	CreateCertificate func(hostname string) (tls.Certificate, error)

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
				log.Printf("gemini: Accept error: %v; retrying in %v", err, tempDelay)
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
		return nil, ErrCertificateNotFound
	}
	cert, err := s.Certificates.Lookup(hostname)

	switch err {
	case ErrCertificateNotFound, ErrCertificateExpired:
		if s.CreateCertificate != nil {
			cert, err := s.CreateCertificate(hostname)
			if err == nil {
				s.Certificates.Add(hostname, cert)
			}
			return &cert, err
		}
	}

	return cert, err
}

// respond responds to a connection.
func (s *Server) respond(conn net.Conn) {
	if d := s.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := s.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}

	r := bufio.NewReader(conn)
	w := newResponseWriter(conn)
	// Read requested URL
	rawurl, err := r.ReadString('\r')
	if err != nil {
		return
	}
	// Read terminating line feed
	if b, err := r.ReadByte(); err != nil {
		return
	} else if b != '\n' {
		w.WriteStatus(StatusBadRequest)
	}
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Ensure URL is valid
	if len(rawurl) > 1024 {
		w.WriteStatus(StatusBadRequest)
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error status if User is specified in the URL
		w.WriteStatus(StatusBadRequest)
	} else {
		// If no scheme is specified, assume a default scheme of gemini://
		if url.Scheme == "" {
			url.Scheme = "gemini"
		}
		req := &Request{
			URL:        url,
			RemoteAddr: conn.RemoteAddr(),
			TLS:        conn.(*tls.Conn).ConnectionState(),
		}
		resp := s.responder(req)
		if resp != nil {
			resp.Respond(w, req)
		} else {
			w.WriteStatus(StatusNotFound)
		}
	}
	w.b.Flush()
	conn.Close()
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

// ResponseWriter is used by a Gemini handler to construct a Gemini response.
type ResponseWriter struct {
	b           *bufio.Writer
	bodyAllowed bool
	wroteHeader bool
	mimetype    string
}

func newResponseWriter(conn net.Conn) *ResponseWriter {
	return &ResponseWriter{
		b: bufio.NewWriter(conn),
	}
}

// WriteHeader writes the response header.
// If the header has already been written, WriteHeader does nothing.
//
// Meta contains more information related to the response status.
// For successful responses, Meta should contain the mimetype of the response.
// For failure responses, Meta should contain a short description of the failure.
// Meta should not be longer than 1024 bytes.
func (w *ResponseWriter) WriteHeader(status Status, meta string) {
	if w.wroteHeader {
		return
	}
	w.b.WriteString(strconv.Itoa(int(status)))
	w.b.WriteByte(' ')
	w.b.WriteString(meta)
	w.b.Write(crlf)

	// Only allow body to be written on successful status codes.
	if status.Class() == StatusClassSuccess {
		w.bodyAllowed = true
	}
	w.wroteHeader = true
}

// WriteStatus writes the response header with the given status code.
//
// WriteStatus is equivalent to WriteHeader(status, status.Message())
func (w *ResponseWriter) WriteStatus(status Status) {
	w.WriteHeader(status, status.Message())
}

// SetMimetype sets the mimetype that will be written for a successful response.
// If the mimetype is not set, it will default to "text/gemini".
func (w *ResponseWriter) SetMimetype(mimetype string) {
	w.mimetype = mimetype
}

// Write writes the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
//
// If the response header has not yet been written, Write calls WriteHeader
// with StatusSuccess and the mimetype set in SetMimetype.
func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		mimetype := w.mimetype
		if mimetype == "" {
			mimetype = "text/gemini"
		}
		w.WriteHeader(StatusSuccess, mimetype)
	}
	if !w.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return w.b.Write(b)
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

// Input returns the request query.
// If the query is invalid or no query is provided, ok will be false.
//
// Example:
//
//    input, ok := gemini.Input(req)
//    if !ok {
//        w.WriteHeader(gemini.StatusInput, "Prompt")
//        return
//    }
//    // ...
//
func Input(r *Request) (query string, ok bool) {
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		query, err := url.QueryUnescape(r.URL.RawQuery)
		return query, err == nil
	}
	return "", false
}

// Certificate returns the request certificate.
// It returns nil if no certificate was provided.
//
// Example:
//
//    cert := gemini.Certificate(req)
//    if cert == nil {
//        w.WriteStatus(gemini.StatusCertificateRequired)
//        return
//    }
//    // ...
//
func Certificate(r *Request) *x509.Certificate {
	if len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
