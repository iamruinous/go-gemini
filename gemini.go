// Package gemini implements the Gemini protocol.
package gemini

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Status codes.
const (
	StatusInput                     = 10
	StatusSensitiveInput            = 11
	StatusSuccess                   = 20
	StatusRedirectTemporary         = 30
	StatusRedirectPermanent         = 31
	StatusTemporaryFailure          = 40
	StatusServerUnavailable         = 41
	StatusCGIError                  = 42
	StatusProxyError                = 43
	StatusSlowDown                  = 44
	StatusPermanentFailure          = 50
	StatusNotFound                  = 51
	StatusGone                      = 52
	StatusProxyRequestRefused       = 53
	StatusBadRequest                = 59
	StatusClientCertificateRequired = 60
	StatusCertificateNotAuthorised  = 61
	StatusCertificateNotValid       = 62
)

// Status code categories.
const (
	StatusClassInput                     = 1
	StatusClassSuccess                   = 2
	StatusClassRedirect                  = 3
	StatusClassTemporaryFailure          = 4
	StatusClassPermanentFailure          = 5
	StatusClassClientCertificateRequired = 6
)

// Errors.
var (
	ErrProtocol       = errors.New("gemini: protocol error")
	ErrInvalidURL     = errors.New("gemini: requested URL is invalid")
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow for body")
)

var (
	crlf = []byte("\r\n")
)

// Request is a Gemini request.
//
// A Request can optionally be configured with a client certificate. Example:
//
//     req := NewRequest(url)
//     cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
//     if err != nil {
//         panic(err)
//     }
//     req.TLSConfig.Certificates = append(req.TLSConfig.Certificates, cert)
//
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host specifies the host on which the URL is sought.
	// If this field is empty, the host will be inferred from the URL.
	// This field is ignored by the server.
	Host string

	// TLSConfig provides a TLS configuration for use by the client.
	// It is recommended that clients set `InsecureSkipVerify` to true to skip
	// verifying TLS certificates, and instead adopt a Trust-On-First-Use
	// method of verifying certificates.
	// This field is ignored by the server.
	TLSConfig tls.Config

	// RemoteAddr allows servers and other software to record the network
	// address that sent the request.
	// This field is ignored by the client.
	RemoteAddr net.Addr

	// TLS allows servers and other software to record information about the TLS
	// connection on which the request was recieved.
	// This field is ignored by the client.
	TLS tls.ConnectionState
}

// NewRequest returns a new request. The host is inferred from the provided url.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	host := u.Host

	// If there is no port, use the default port of 1965
	if u.Port() == "" {
		host += ":1965"
	}

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// NewProxyRequest returns a new request using the provided host.
// The provided host must contain a port.
func NewProxyRequest(host, rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// write writes the Gemini request to the provided buffered writer.
func (r *Request) write(w *bufio.Writer) error {
	url := r.URL.String()
	// UserInfo is invalid
	if r.URL.User != nil || len(url) > 1024 {
		return ErrInvalidURL
	}
	if _, err := w.WriteString(url); err != nil {
		return err
	}
	if _, err := w.Write(crlf); err != nil {
		return err
	}
	return nil
}

// Response is a Gemini response.
type Response struct {
	// Status represents the response status.
	Status int

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the mimetype of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	// Body contains the response body.
	Body []byte

	// TLS contains information about the TLS connection on which the response
	// was received.
	TLS tls.ConnectionState
}

// Get makes a request for the provided URL. The host is inferred from the URL.
func Get(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return Do(req)
}

// ProxyGet requests the provided URL from the provided host.
func ProxyGet(host, url string) (*Response, error) {
	req, err := NewProxyRequest(host, url)
	if err != nil {
		return nil, err
	}
	return Do(req)
}

// Do sends a Gemini request and returns a Gemini response.
func Do(req *Request) (*Response, error) {
	// Connect to the host
	conn, err := tls.Dial("tcp", req.Host, &req.TLSConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	// TODO: Is buffered I/O necessary here?
	w := bufio.NewWriter(conn)
	req.write(w)
	if err := w.Flush(); err != nil {
		return nil, err
	}

	// Read the response status
	r := bufio.NewReader(conn)
	statusB := make([]byte, 2)
	if _, err := r.Read(statusB); err != nil {
		return nil, err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return nil, err
	}

	// Read one space
	if b, err := r.ReadByte(); err != nil {
		return nil, err
	} else if b != ' ' {
		return nil, ErrProtocol
	}

	// Read the meta
	meta, err := r.ReadString('\r')
	if err != nil {
		return nil, err
	}

	// Read terminating newline
	if b, err := r.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrProtocol
	}

	// Trim carriage return
	meta = meta[:len(meta)-1]

	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return nil, ErrProtocol
	}

	// Read response body
	var body []byte
	if status/10 == StatusClassSuccess {
		var err error
		body, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}

	return &Response{
		Status: status,
		Meta:   meta,
		Body:   body,
		TLS:    conn.ConnectionState(),
	}, nil
}

// Server is a Gemini server.
type Server struct {
	// Addr specifies the address that the server should listen on.
	// If Addr is empty, the server will listen on the address ":1965".
	Addr string

	// TLSConfig provides a TLS configuration for use by the server.
	TLSConfig tls.Config

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

	tlsListener := tls.NewListener(ln, &s.TLSConfig)
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
	wroteHeader bool
	bodyAllowed bool
}

func newResponseWriter(conn net.Conn) *ResponseWriter {
	return &ResponseWriter{
		w: bufio.NewWriter(conn),
	}
}

// WriteHeader writes the response header.
//
// Meta contains more information related to the response status.
// For successful responses, Meta should contain the mimetype of the response.
// For failure responses, Meta should contain a short description of the failure.
// Meta should not be longer than 1024 bytes.
func (r *ResponseWriter) WriteHeader(status int, meta string) {
	r.w.WriteString(strconv.Itoa(status))
	r.w.WriteByte(' ')
	r.w.WriteString(meta)
	r.w.Write(crlf)

	// Only allow body to be written on successful status codes.
	if status/10 == StatusClassSuccess {
		r.bodyAllowed = true
	}
}

// Write writes the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
// WriteHeader must be called before Write.
func (r *ResponseWriter) Write(b []byte) (int, error) {
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
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Read terminating line feed
	if b, err := r.ReadByte(); err != nil {
		return
	} else if b != '\n' {
		rw.WriteHeader(StatusBadRequest, "Bad request")
	}

	if len(rawurl) > 1024 {
		rw.WriteHeader(StatusBadRequest, "Requested URL exceeds 1024 bytes")
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error status if User is specified in the URL
		rw.WriteHeader(StatusBadRequest, "Requested URL is invalid")
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

// ServeMux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that most closesly matches
// the URL.
type ServeMux struct {
	entries []muxEntry
}

type muxEntry struct {
	scheme  string
	host    string
	path    string
	handler Handler
}

func (m *ServeMux) match(url *url.URL) Handler {
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
func (m *ServeMux) Handle(pattern string, handler Handler) {
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
func (m *ServeMux) HandleFunc(pattern string, handlerFunc func(*ResponseWriter, *Request)) {
	handler := HandlerFunc(handlerFunc)
	m.Handle(pattern, handler)
}

// Serve responds to the request with the appropriate handler.
func (m *ServeMux) Serve(rw *ResponseWriter, req *Request) {
	h := m.match(req.URL)
	if h == nil {
		rw.WriteHeader(StatusNotFound, "Not found")
		return
	}
	h.Serve(rw, req)
}

// A wrapper around a bare function that implements Handler.
type HandlerFunc func(*ResponseWriter, *Request)

func (f HandlerFunc) Serve(rw *ResponseWriter, req *Request) {
	f(rw, req)
}
