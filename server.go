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

	// Certificates contains the certificates used by the server.
	Certificates CertificateStore

	// CreateCertificate, if not nil, will be called to create a new certificate
	// if the current one is expired or missing.
	CreateCertificate func(hostname string) (tls.Certificate, error)

	// registered responders
	responders map[responderKey]Responder
}

type responderKey struct {
	scheme   string
	hostname string
	wildcard bool
}

// Register registers a responder for the given pattern.
//
// Patterns must be in the form of hostname or scheme://hostname
// (e.g. gemini://example.com).
// If no scheme is specified, a default scheme of gemini:// is assumed.
//
// Wildcard patterns are supported (e.g. *.example.com).
// To register a certificate for a wildcard hostname, call Certificates.Add:
//
//     var s gemini.Server
//     s.Certificates.Add("*.example.com", cert)
func (s *Server) Register(pattern string, responder Responder) {
	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if responder == nil {
		panic("gemini: nil responder")
	}
	if s.responders == nil {
		s.responders = map[responderKey]Responder{}
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
	split = strings.SplitN(key.hostname, ".", 2)
	if len(split) == 2 && split[0] == "*" {
		key.hostname = split[1]
		key.wildcard = true
	}

	if _, ok := s.responders[key]; ok {
		panic("gemini: multiple registrations for " + pattern)
	}
	s.responders[key] = responder
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
	cert, err := s.Certificates.Lookup(h.ServerName)
	switch err {
	case ErrCertificateExpired, ErrCertificateUnknown:
		if s.CreateCertificate != nil {
			cert, err := s.CreateCertificate(h.ServerName)
			if err == nil {
				s.Certificates.Add(h.ServerName, cert)
			}
			return &cert, err
		}
	}
	return cert, err
}

// respond responds to a connection.
func (s *Server) respond(conn net.Conn) {
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
		w.WriteHeader(StatusBadRequest, "Bad request")
	}
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Ensure URL is valid
	if len(rawurl) > 1024 {
		w.WriteHeader(StatusBadRequest, "Bad request")
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error status if User is specified in the URL
		w.WriteHeader(StatusBadRequest, "Bad request")
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
	if h, ok := s.responders[responderKey{r.URL.Scheme, r.URL.Hostname(), false}]; ok {
		return h
	}
	wildcard := strings.SplitN(r.URL.Hostname(), ".", 2)
	if len(wildcard) == 2 {
		if h, ok := s.responders[responderKey{r.URL.Scheme, wildcard[1], true}]; ok {
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
func (w *ResponseWriter) WriteStatus(status Status) {
	w.WriteHeader(status, status.Message())
}

// SetMimetype sets the mimetype that will be written for a successful response.
// The provided mimetype will only be used if Write is called without calling
// WriteHeader.
// If the mimetype is not set, it will default to "text/gemini".
func (w *ResponseWriter) SetMimetype(mimetype string) {
	w.mimetype = mimetype
}

// Write writes the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
//
// If WriteHeader has not yet been called, Write calls
// WriteHeader(StatusSuccess, mimetype) where mimetype is the mimetype set in
// SetMimetype. If no mimetype is set, a default of "text/gemini" will be used.
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

// Input returns the request query.
// If no input is provided, it responds with StatusInput.
func Input(w *ResponseWriter, r *Request, prompt string) (string, bool) {
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		query, err := url.QueryUnescape(r.URL.RawQuery)
		return query, err == nil
	}
	w.WriteHeader(StatusInput, prompt)
	return "", false
}

// SensitiveInput returns the request query.
// If no input is provided, it responds with StatusSensitiveInput.
func SensitiveInput(w *ResponseWriter, r *Request, prompt string) (string, bool) {
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		query, err := url.QueryUnescape(r.URL.RawQuery)
		return query, err == nil
	}
	w.WriteHeader(StatusSensitiveInput, prompt)
	return "", false
}

// Redirect replies to the request with a redirect to the given URL.
func Redirect(w *ResponseWriter, url string) {
	w.WriteHeader(StatusRedirect, url)
}

// PermanentRedirect replies to the request with a permanent redirect to the given URL.
func PermanentRedirect(w *ResponseWriter, url string) {
	w.WriteHeader(StatusRedirectPermanent, url)
}

// Certificate returns the request certificate. If one is not provided,
// it returns nil and responds with StatusCertificateRequired.
func Certificate(w *ResponseWriter, r *Request) (*x509.Certificate, bool) {
	if len(r.TLS.PeerCertificates) == 0 {
		w.WriteStatus(StatusCertificateRequired)
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
}

// ResponderFunc is a wrapper around a bare function that implements Responder.
type ResponderFunc func(*ResponseWriter, *Request)

func (f ResponderFunc) Respond(w *ResponseWriter, r *Request) {
	f(w, r)
}
