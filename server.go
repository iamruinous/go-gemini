package gmi

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server errors.
var (
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow for body")
	ErrNotAFile       = errors.New("gemini: not a file")
)

// Server is a Gemini server.
type Server struct {
	// Addr specifies the address that the server should listen on.
	// If Addr is empty, the server will listen on the address ":1965".
	Addr string

	// Certificate provides a TLS certificate for use by the server.
	// Using a self-signed certificate is recommended.
	Certificate tls.Certificate

	// Handler specifies the Handler for requests.
	// If Handler is not set, the server will error.
	Handler Handler
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

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{s.Certificate},
		ClientAuth:         tls.RequestClientCert,
	}
	tlsListener := tls.NewListener(ln, config)
	return s.Serve(tlsListener)
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

// ResponseWriter is used by a Gemini handler to construct a Gemini response.
type ResponseWriter struct {
	w           *bufio.Writer
	bodyAllowed bool
	wroteHeader bool
	mimetype    string
}

func newResponseWriter(conn net.Conn) *ResponseWriter {
	return &ResponseWriter{
		w: bufio.NewWriter(conn),
	}
}

// WriteHeader writes the response header.
// If the header has already been written, WriteHeader does nothing.
//
// Meta contains more information related to the response status.
// For successful responses, Meta should contain the mimetype of the response.
// For failure responses, Meta should contain a short description of the failure.
// Meta should not be longer than 1024 bytes.
func (r *ResponseWriter) WriteHeader(status int, meta string) {
	if r.wroteHeader {
		return
	}
	r.w.WriteString(strconv.Itoa(status))
	r.w.WriteByte(' ')
	r.w.WriteString(meta)
	r.w.Write(crlf)

	// Only allow body to be written on successful status codes.
	if status/10 == StatusClassSuccess {
		r.bodyAllowed = true
	}
	r.wroteHeader = true
}

// SetMimetype sets the mimetype that will be written for a successful response.
// The provided mimetype will only be used if Write is called without calling
// WriteHeader.
// If the mimetype is not set, it will default to "text/gemini".
func (r *ResponseWriter) SetMimetype(mimetype string) {
	r.mimetype = mimetype
}

// Write writes the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
//
// If WriteHeader has not yet been called, Write calls
// WriteHeader(StatusSuccess, mimetype) where mimetype is the mimetype set in
// SetMimetype. If no mimetype is set, a default of "text/gemini" will be used.
func (r *ResponseWriter) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		mimetype := r.mimetype
		if mimetype == "" {
			mimetype = "text/gemini"
		}
		r.WriteHeader(StatusSuccess, mimetype)
	}
	if !r.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return r.w.Write(b)
}

// respond responds to a connection.
func (s *Server) respond(conn net.Conn) {
	r := bufio.NewReader(conn)
	rw := newResponseWriter(conn)
	// Read requested URL
	rawurl, err := r.ReadString('\r')
	if err != nil {
		return
	}
	// Read terminating line feed
	if b, err := r.ReadByte(); err != nil {
		return
	} else if b != '\n' {
		rw.WriteHeader(StatusBadRequest, "Bad request")
	}
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Ensure URL is valid
	if len(rawurl) > 1024 {
		rw.WriteHeader(StatusBadRequest, "Bad request")
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error status if User is specified in the URL
		rw.WriteHeader(StatusBadRequest, "Bad request")
	} else {
		// Gather information about the request
		req := &Request{
			URL:        url,
			RemoteAddr: conn.RemoteAddr(),
			TLS:        conn.(*tls.Conn).ConnectionState(),
		}
		s.Handler.Serve(rw, req)
	}
	rw.w.Flush()
	conn.Close()
}

// A Handler responds to a Gemini request.
type Handler interface {
	// Serve accepts a Request and constructs a Response.
	Serve(*ResponseWriter, *Request)
}

// Input responds to the request with a request for input using the given prompt.
func Input(rw *ResponseWriter, req *Request, prompt string) {
	rw.WriteHeader(StatusInput, prompt)
}

// InputHandler returns a simple handler that responds to each request with
// a request for input.
func InputHandler(prompt string) Handler {
	return HandlerFunc(func(rw *ResponseWriter, req *Request) {
		Input(rw, req, prompt)
	})
}

// WithInput either responds to the request with StatusInput if no input
// is provided, or calls f with the input when provided.
func WithInput(rw *ResponseWriter, req *Request, prompt string, f func(string)) {
	input := req.URL.RawQuery
	if input == "" {
		Input(rw, req, prompt)
		return
	}
	f(input)
}

// Sensitive responds to the request with a request for sensitive input
// using the given prompt.
func SensitiveInput(rw *ResponseWriter, req *Request, prompt string) {
	rw.WriteHeader(StatusSensitiveInput, prompt)
}

// SensitiveInputHandler returns a simpler handler that responds to each request
// with a request for sensitive input.
func SensitiveInputHandler(prompt string) Handler {
	return HandlerFunc(func(rw *ResponseWriter, req *Request) {
		SensitiveInput(rw, req, prompt)
	})
}

// WithSensitiveInput either responds to the request with StatusSensitiveInput
// if no input is provided, or calls f with the input when provided.
func WithSensitiveInput(rw *ResponseWriter, req *Request, prompt string, f func(string)) {
	input := req.URL.RawQuery
	if input == "" {
		SensitiveInput(rw, req, prompt)
		return
	}
	f(input)
}

// Redirect replies to the request with a redirect to the given URL.
func Redirect(rw *ResponseWriter, req *Request, url string) {
	rw.WriteHeader(StatusRedirect, url)
}

// RedirectHandler returns a simple handler that responds to each request with
// a redirect to the given URL.
// If permanent is true, the handler will respond with a permanent redirect.
func RedirectHandler(url string) Handler {
	return HandlerFunc(func(rw *ResponseWriter, req *Request) {
		Redirect(rw, req, url)
	})
}

// PermanentRedirect replies to the request with a permanent redirect to the given URL.
func PermanentRedirect(rw *ResponseWriter, req *Request, url string) {
	rw.WriteHeader(StatusRedirectPermanent, url)
}

// PermanentRedirectHandler returns a simple handler that responds to each request with
// a redirect to the given URL.
// If permanent is true, the handler will respond with a permanent redirect.
func PermanentRedirectHandler(url string) Handler {
	return HandlerFunc(func(rw *ResponseWriter, req *Request) {
		PermanentRedirect(rw, req, url)
	})
}

// NotFound replies to the request with the NotFound status code.
func NotFound(rw *ResponseWriter, req *Request) {
	rw.WriteHeader(StatusNotFound, "Not found")
}

// NotFoundHandler returns a simple handler that responds to each request with
// the status code NotFound.
func NotFoundHandler() Handler {
	return HandlerFunc(NotFound)
}

// Gone replies to the request with the Gone status code.
func Gone(rw *ResponseWriter, req *Request) {
	rw.WriteHeader(StatusGone, "Gone")
}

// GoneHandler returns a simple handler that responds to each request with
// the status code Gone.
func GoneHandler() Handler {
	return HandlerFunc(Gone)
}

// CertificateRequired responds to the request with the CertificateRequired
// status code.
func CertificateRequired(rw *ResponseWriter, req *Request) {
	rw.WriteHeader(StatusCertificateRequired, "Certificate required")
}

// CertificateNotAuthorized responds to the request with
// the CertificateNotAuthorized status code.
func CertificateNotAuthorized(rw *ResponseWriter, req *Request) {
	rw.WriteHeader(StatusCertificateNotAuthorized, "Certificate not authorized")
}

// WithCertificate responds with CertificateRequired if the client did not
// provide a certificate, and calls f with the first ceritificate if they did.
func WithCertificate(rw *ResponseWriter, req *Request, f func(*x509.Certificate)) {
	if len(req.TLS.PeerCertificates) == 0 {
		CertificateRequired(rw, req)
		return
	}
	cert := req.TLS.PeerCertificates[0]
	f(cert)
}

// CertificateHandler returns a simple handler that requests a certificate from
// clients if they did not provide one, and calls f with the first certificate
// if they did.
func CertificateHandler(f func(*x509.Certificate)) Handler {
	return HandlerFunc(func(rw *ResponseWriter, req *Request) {
		WithCertificate(rw, req, f)
	})
}

// ServeMux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that most closesly matches
// the URL.
type ServeMux struct {
	entries []muxEntry
}

type muxEntry struct {
	u       *url.URL
	handler Handler
}

func (m *ServeMux) match(url *url.URL) Handler {
	for _, e := range m.entries {
		if (e.u.Scheme == "" || url.Scheme == e.u.Scheme) &&
			(e.u.Host == "" || url.Host == e.u.Host) &&
			strings.HasPrefix(url.Path, e.u.Path) {
			return e.handler
		}
	}
	return nil
}

// Handle registers a Handler for the given pattern.
func (m *ServeMux) Handle(pattern string, handler Handler) {
	url, err := url.Parse(pattern)
	if err != nil {
		panic(err)
	}
	e := muxEntry{
		url,
		handler,
	}
	m.entries = appendSorted(m.entries, e)
}

// HandleFunc registers a HandlerFunc for the given pattern.
func (m *ServeMux) HandleFunc(pattern string, handlerFunc func(*ResponseWriter, *Request)) {
	handler := HandlerFunc(handlerFunc)
	m.Handle(pattern, handler)
}

// Serve responds to the request with the appropriate handler.
func (m *ServeMux) Serve(rw *ResponseWriter, req *Request) {
	h := m.match(req.URL)
	if h == nil {
		NotFound(rw, req)
		return
	}
	h.Serve(rw, req)
}

// appendSorted appends the entry e in the proper place in entries.
func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
	n := len(es)
	// sort by length
	i := sort.Search(n, func(i int) bool {
		// Sort entries by length.
		// - Entries with a scheme take preference over entries without.
		// - Entries with a host take preference over entries without.
		// - Longer paths take preference over shorter paths.
		return (es[i].u.Scheme == "" || (e.u.Scheme != "" && len(es[i].u.Scheme) < len(e.u.Scheme))) &&
			(es[i].u.Host == "" || (e.u.Host != "" && len(es[i].u.Host) < len(e.u.Host))) &&
			len(es[i].u.Path) < len(e.u.Path)
	})
	if i == n {
		return append(es, e)
	}
	// we now know that i points at where we want to insert
	es = append(es, muxEntry{}) // try to grow the slice in place, any entry works.
	copy(es[i+1:], es[i:])      // Move shorter entries down
	es[i] = e
	return es
}

// A wrapper around a bare function that implements Handler.
type HandlerFunc func(*ResponseWriter, *Request)

func (f HandlerFunc) Serve(rw *ResponseWriter, req *Request) {
	f(rw, req)
}

// ServeDir serves files from a directory.
type ServeDir struct {
	path string // path to the directory
}

// FileServer takes a filesystem and returns a handler which uses that filesystem.
// The returned Handler rejects requests containing '..' in them.
func FileServer(fsys FS) Handler {
	return fsHandler{
		fsys,
	}
}

type fsHandler struct {
	FS
}

func (fsys fsHandler) Serve(rw *ResponseWriter, req *Request) {
	// Reject requests with '..' in them
	if containsDotDot(req.URL.Path) {
		NotFound(rw, req)
		return
	}
	f, err := fsys.Open(req.URL.Path)
	if err != nil {
		NotFound(rw, req)
		return
	}
	// TODO: detect mimetype
	rw.SetMimetype("text/gemini")
	// Copy file to response writer
	io.Copy(rw, f)
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

// TODO: replace with fs.FS when available
type FS interface {
	Open(name string) (File, error)
}

// TODO: replace with fs.File when available
type File interface {
	Stat() (os.FileInfo, error)
	Read([]byte) (int, error)
	Close() error
}

// Dir implements FS using the native filesystem restricted to a specific directory.
type Dir string

func (d Dir) Open(name string) (File, error) {
	path := filepath.Join(string(d), name)
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	if stat, err := f.Stat(); err == nil {
		if !stat.Mode().IsRegular() {
			return nil, ErrNotAFile
		}
	}
	return f, nil
}
