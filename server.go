package gemini

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
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
	GetCertificate func(hostname string, store *CertificateStore) *tls.Certificate

	// registered responders
	responders map[responderKey]Responder
}

type responderKey struct {
	scheme   string
	hostname string
	wildcard bool
}

// Register registers a responder for the given pattern.
// Patterns must be in the form of scheme://hostname (e.g. gemini://example.com).
// If no scheme is specified, a default scheme of gemini:// is assumed.
// Wildcard patterns are supported (e.g. *.example.com).
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

	config := &tls.Config{
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.GetCertificate != nil {
				return s.GetCertificate(h.ServerName, &s.CertificateStore), nil
			}
			return s.CertificateStore.Lookup(h.ServerName)
		},
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
		s.responder(req).Respond(w, req)
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
	return ResponderFunc(NotFound)
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
func (w *ResponseWriter) WriteHeader(status int, meta string) {
	if w.wroteHeader {
		return
	}
	w.b.WriteString(strconv.Itoa(status))
	w.b.WriteByte(' ')
	w.b.WriteString(meta)
	w.b.Write(crlf)

	// Only allow body to be written on successful status codes.
	if status/10 == StatusClassSuccess {
		w.bodyAllowed = true
	}
	w.wroteHeader = true
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
		return r.URL.RawQuery, true
	}
	w.WriteHeader(StatusInput, prompt)
	return "", false
}

// SensitiveInput returns the request query.
// If no input is provided, it responds with StatusSensitiveInput.
func SensitiveInput(w *ResponseWriter, r *Request, prompt string) (string, bool) {
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		return r.URL.RawQuery, true
	}
	w.WriteHeader(StatusSensitiveInput, prompt)
	return "", false
}

// Redirect replies to the request with a redirect to the given URL.
func Redirect(w *ResponseWriter, r *Request, url string) {
	w.WriteHeader(StatusRedirect, url)
}

// PermanentRedirect replies to the request with a permanent redirect to the given URL.
func PermanentRedirect(w *ResponseWriter, r *Request, url string) {
	w.WriteHeader(StatusRedirectPermanent, url)
}

// NotFound replies to the request with the NotFound status code.
func NotFound(w *ResponseWriter, r *Request) {
	w.WriteHeader(StatusNotFound, "Not found")
}

// Gone replies to the request with the Gone status code.
func Gone(w *ResponseWriter, r *Request) {
	w.WriteHeader(StatusGone, "Gone")
}

// CertificateRequired responds to the request with the CertificateRequired
// status code.
func CertificateRequired(w *ResponseWriter, r *Request) {
	w.WriteHeader(StatusCertificateRequired, "Certificate required")
}

// CertificateNotAuthorized responds to the request with
// the CertificateNotAuthorized status code.
func CertificateNotAuthorized(w *ResponseWriter, r *Request) {
	w.WriteHeader(StatusCertificateNotAuthorized, "Certificate not authorized")
}

// Certificate returns the request certificate. If one is not provided,
// it returns nil and responds with StatusCertificateRequired.
func Certificate(w *ResponseWriter, r *Request) (*x509.Certificate, bool) {
	if len(r.TLS.PeerCertificates) == 0 {
		CertificateRequired(w, r)
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
}

// ResponderFunc is a wrapper around a bare function that implements Handler.
type ResponderFunc func(*ResponseWriter, *Request)

func (f ResponderFunc) Respond(w *ResponseWriter, r *Request) {
	f(w, r)
}

// The following code is modified from the net/http package.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	r       Responder
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
func (mux *ServeMux) match(path string) Responder {
	// Check for exact match first.
	v, ok := mux.m[path]
	if ok {
		return v.r
	}

	// Check for longest valid match.  mux.es contains all patterns
	// that end in / sorted from longest to shortest.
	for _, e := range mux.es {
		if strings.HasPrefix(path, e.pattern) {
			return e.r
		}
	}
	return nil
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

// Respond dispatches the request to the responder whose
// pattern most closely matches the request URL.
func (mux *ServeMux) Respond(w *ResponseWriter, r *Request) {
	path := cleanPath(r.URL.Path)

	// If the given path is /tree and its handler is not registered,
	// redirect for /tree/.
	if u, ok := mux.redirectToPathSlash(path, r.URL); ok {
		Redirect(w, r, u.String())
		return
	}

	if path != r.URL.Path {
		u := *r.URL
		u.Path = path
		Redirect(w, r, u.String())
		return
	}

	mux.mu.RLock()
	defer mux.mu.RUnlock()

	resp := mux.match(path)
	if resp == nil {
		NotFound(w, r)
		return
	}
	resp.Respond(w, r)
}

// Handle registers the responder for the given pattern.
// If a responder already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, responder Responder) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if responder == nil {
		panic("gemini: nil responder")
	}
	if _, exist := mux.m[pattern]; exist {
		panic("gemini: multiple registrations for " + pattern)
	}

	if mux.m == nil {
		mux.m = make(map[string]muxEntry)
	}
	e := muxEntry{responder, pattern}
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

// HandleFunc registers the responder function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, responder func(*ResponseWriter, *Request)) {
	if responder == nil {
		panic("gemini: nil responder")
	}
	mux.Handle(pattern, ResponderFunc(responder))
}
