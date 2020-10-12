package gmi

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server errors.
var (
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow for body")
)

// Server is a Gemini server.
type Server struct {
	// Addr specifies the address that the server should listen on.
	// If Addr is empty, the server will listen on the address ":1965".
	Addr string

	// CertificateStore contains the certificates used by the server.
	CertificateStore CertificateStore

	// GetCertificate, if not nil, will be called to retrieve the certificate
	// to use for a given hostname.
	// If the certificate is nil, the connection will be aborted.
	GetCertificate func(hostname string) *tls.Certificate

	// registered handlers
	handlers []handlerEntry
}

// Handle registers a handler for the given host.
// A default scheme of gemini:// is assumed.
func (s *Server) Handle(host string, handler Handler) {
	if host == "" {
		panic("gmi: invalid host")
	}
	if handler == nil {
		panic("gmi: nil handler")
	}
	s.HandleScheme("gemini", host, handler)
}

// HandleScheme registers a handler for the given scheme and host.
func (s *Server) HandleScheme(scheme string, host string, handler Handler) {
	s.handlers = append(s.handlers, handlerEntry{
		scheme,
		host,
		handler,
	})
}

type handlerEntry struct {
	scheme string
	host   string
	h      Handler
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
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.GetCertificate != nil {
				return s.GetCertificate(h.ServerName), nil
			}
			return s.CertificateStore.Lookup(h.ServerName)
		},
		ClientAuth: tls.RequestClientCert,
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
		s.handler(req).Serve(rw, req)
	}
	rw.w.Flush()
	conn.Close()
}

func (s *Server) handler(req *Request) Handler {
	for _, e := range s.handlers {
		if req.URL.Scheme != e.scheme {
			continue
		}
		// Allow host or bare hostname
		if req.URL.Host == e.host || req.Hostname() == e.host {
			return e.h
		}
	}
	return NotFoundHandler()
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

// WithCertificate either responds with CertificateRequired if the client did
// not provide a certificate, or calls f with the first ceritificate provided.
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

// HandlerFunc is a wrapper around a bare function that implements Handler.
type HandlerFunc func(*ResponseWriter, *Request)

func (f HandlerFunc) Serve(rw *ResponseWriter, req *Request) {
	f(rw, req)
}

// The following code is modified from the net/http package.

// ServeMux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that
// most closely matches the URL.
//
// Patterns name fixed, rooted paths, like "/favicon.ico",
// or rooted subtrees, like "/images/" (note the trailing slash).
// Longer patterns take precedence over shorter ones, so that
// if there are handlers registered for both "/images/"
// and "/images/thumbnails/", the latter handler will be
// called for paths beginning "/images/thumbnails/" and the
// former will receive requests for any other paths in the
// "/images/" subtree.
//
// Note that since a pattern ending in a slash names a rooted subtree,
// the pattern "/" matches all paths not matched by other registered
// patterns, not just the URL with Path == "/".
//
// If a subtree has been registered and a request is received naming the
// subtree root without its trailing slash, ServeMux redirects that
// request to the subtree root (adding the trailing slash). This behavior can
// be overridden with a separate registration for the path without
// the trailing slash. For example, registering "/images/" causes ServeMux
// to redirect a request for "/images" to "/images/", unless "/images" has
// been registered separately.
//
// ServeMux also takes care of sanitizing the URL request path and
// redirecting any request containing . or .. elements or repeated slashes
// to an equivalent, cleaner URL.
type ServeMux struct {
	mu sync.RWMutex
	m  map[string]muxEntry
	es []muxEntry // slice of entries sorted from longest to shortest.
}

type muxEntry struct {
	h       Handler
	pattern string
}

// cleanPath returns the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		// Fast path for common case of p being the string we want:
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

// Find a handler on a handler map given a path string.
// Most-specific (longest) pattern wins.
func (mux *ServeMux) match(path string) (h Handler, pattern string) {
	// Check for exact match first.
	v, ok := mux.m[path]
	if ok {
		return v.h, v.pattern
	}

	// Check for longest valid match.  mux.es contains all patterns
	// that end in / sorted from longest to shortest.
	for _, e := range mux.es {
		if strings.HasPrefix(path, e.pattern) {
			return e.h, e.pattern
		}
	}
	return nil, ""
}

// redirectToPathSlash determines if the given path needs appending "/" to it.
// This occurs when a handler for path + "/" was already registered, but
// not for path itself. If the path needs appending to, it creates a new
// URL, setting the path to u.Path + "/" and returning true to indicate so.
func (mux *ServeMux) redirectToPathSlash(path string, u *url.URL) (*url.URL, bool) {
	mux.mu.RLock()
	shouldRedirect := mux.shouldRedirectRLocked(path)
	mux.mu.RUnlock()
	if !shouldRedirect {
		return u, false
	}
	path = path + "/"
	u = &url.URL{Path: path, RawQuery: u.RawQuery}
	return u, true
}

// shouldRedirectRLocked reports whether the given path and host should be redirected to
// path+"/". This should happen if a handler is registered for path+"/" but
// not path -- see comments at ServeMux.
func (mux *ServeMux) shouldRedirectRLocked(path string) bool {
	if _, exist := mux.m[path]; exist {
		return false
	}

	n := len(path)
	if n == 0 {
		return false
	}
	if _, exist := mux.m[path+"/"]; exist {
		return path[n-1] != '/'
	}

	return false
}

// Handler returns the handler to use for the given request.
// It consults r.URL.Path. It always returns a non-nil handler.
// If the path is not in its canonical form, the
// handler will be an internally-generated handler that redirects
// to the canonical path. If the host contains a port, it is ignored
// when matching handlers.
//
// Handler also returns the registered pattern that matches the
// request or, in the case of internally-generated redirects,
// the pattern that will match after following the redirect.
//
// If there is no registered handler that applies to the request,
// Handler returns a "not found" handler and an empty pattern.
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {
	path := cleanPath(r.URL.Path)

	// If the given path is /tree and its handler is not registered,
	// redirect for /tree/.
	if u, ok := mux.redirectToPathSlash(path, r.URL); ok {
		return RedirectHandler(u.String()), u.Path
	}

	if path != r.URL.Path {
		_, pattern = mux.handler(path)
		url := *r.URL
		url.Path = path
		return RedirectHandler(url.String()), pattern
	}

	return mux.handler(r.URL.Path)
}

// handler is the main implementation of Handler.
// The path is known to be in canonical form.
func (mux *ServeMux) handler(path string) (h Handler, pattern string) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	h, pattern = mux.match(path)
	if h == nil {
		h, pattern = NotFoundHandler(), ""
	}
	return
}

// Serve dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *ServeMux) Serve(w *ResponseWriter, r *Request) {
	h, _ := mux.Handler(r)
	h.Serve(w, r)
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("gmi: invalid pattern")
	}
	if handler == nil {
		panic("gmi: nil handler")
	}
	if _, exist := mux.m[pattern]; exist {
		panic("gmi: multiple registrations for " + pattern)
	}

	if mux.m == nil {
		mux.m = make(map[string]muxEntry)
	}
	e := muxEntry{h: handler, pattern: pattern}
	mux.m[pattern] = e
	if pattern[len(pattern)-1] == '/' {
		mux.es = appendSorted(mux.es, e)
	}
}

func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
	n := len(es)
	i := sort.Search(n, func(i int) bool {
		return len(es[i].pattern) < len(e.pattern)
	})
	if i == n {
		return append(es, e)
	}
	// we now know that i points at where we want to insert
	es = append(es, muxEntry{}) // try to grow the slice in place, any entry works.
	copy(es[i+1:], es[i:])      // move shorter entries down
	es[i] = e
	return es
}

// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(*ResponseWriter, *Request)) {
	if handler == nil {
		panic("gmi: nil handler")
	}
	mux.Handle(pattern, HandlerFunc(handler))
}
