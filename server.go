package gemini

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"strings"
)

// Server is a Gemini server.
type Server struct {
	Addr      string
	TLSConfig tls.Config
	Handler   Handler
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

	tlsListener := tls.NewListener(ln, &s.TLSConfig)
	return s.Serve(tlsListener)
}

// Serve listens for requests on the provided listener.
func (s *Server) Serve(ln net.Listener) error {
	for {
		rw, err := ln.Accept()
		if err != nil {
			return err
		}

		var resp *Response

		if rawurl, err := readLine(rw); err != nil {
			resp = &Response{
				Status: StatusBadRequest,
				Meta:   "Bad request",
			}
		} else if len(rawurl) > 1024 {
			resp = &Response{
				Status: StatusBadRequest,
				Meta:   "URL exceeds 1024 bytes",
			}
		} else if url, err := url.Parse(rawurl); err != nil {
			resp = &Response{
				Status: StatusBadRequest,
				Meta:   "Invalid URL",
			}
		} else {
			// Gather information about the request
			reqInfo := &RequestInfo{
				URL:          url,
				Certificates: rw.(*tls.Conn).ConnectionState().PeerCertificates,
				RemoteAddr:   rw.RemoteAddr(),
			}
			resp = s.Handler.Serve(reqInfo)
		}

		resp.Write(rw)
		rw.Close()
	}
}

// RequestInfo contains information about a request.
type RequestInfo struct {
	URL          *url.URL            // the requested URL
	Certificates []*x509.Certificate // client certificates
	RemoteAddr   net.Addr            // client remote address
}

// A Handler responds to a Gemini request.
type Handler interface {
	// Serve accepts a Request and returns a Response.
	Serve(*RequestInfo) *Response
}

// Mux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that most closesly matches
// the URL.
type Mux struct {
	entries []muxEntry
}

type muxEntry struct {
	scheme  string
	host    string
	path    string
	handler Handler
}

func (m *Mux) match(url *url.URL) Handler {
	for _, e := range m.entries {
		if (e.scheme == "" || url.Scheme == e.scheme) &&
			(e.host == "" || url.Host == e.host) &&
			strings.HasPrefix(url.Path, e.path) {
			return e.handler
		}
	}
	return nil
}

// Handle registers a Handler for the given pattern.
func (m *Mux) Handle(pattern string, handler Handler) {
	url, err := url.Parse(pattern)
	if err != nil {
		panic(err)
	}
	m.entries = append(m.entries, muxEntry{
		url.Scheme,
		url.Host,
		url.Path,
		handler,
	})
}

// HandleFunc registers a HandlerFunc for the given pattern.
func (m *Mux) HandleFunc(pattern string, handlerFunc func(req *RequestInfo) *Response) {
	handler := HandlerFunc(handlerFunc)
	m.Handle(pattern, handler)
}

// Serve responds to the request with the appropriate handler.
func (m *Mux) Serve(req *RequestInfo) *Response {
	h := m.match(req.URL)
	if h == nil {
		return &Response{
			Status: StatusNotFound,
			Meta:   "Not found",
		}
	}
	return h.Serve(req)
}

// A wrapper around a bare function that implements Handler.
type HandlerFunc func(req *RequestInfo) *Response

func (f HandlerFunc) Serve(req *RequestInfo) *Response {
	return f(req)
}
