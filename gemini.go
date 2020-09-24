// Package gemini implements the Gemini protocol.
package gemini

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
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
	ErrProtocol   = errors.New("Protocol error")
	ErrInvalidURL = errors.New("Invalid URL")
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
	// If this field is not set, the host will be inferred from the URL.
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

// Write writes the Gemini request to the provided io.Writer.
func (r *Request) Write(w io.Writer) error {
	url := r.URL.String()
	// UserInfo is invalid
	if r.URL.User != nil || len(url) > 1024 {
		return ErrInvalidURL
	}
	request := url + "\r\n"
	_, err := w.Write([]byte(request))
	return err
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
	// Body is only used by the server for successful responses.
	Body []byte

	// TLS contains information about the TLS connection on which the response
	// was received.
	// This field is ignored by the server.
	TLS tls.ConnectionState
}

// Write writes the Gemini response header and body to the provided io.Writer.
func (r *Response) Write(w io.Writer) error {
	header := strconv.Itoa(r.Status) + " " + r.Meta + "\r\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return err
	}

	// Only write the response body on success
	if r.Status/10 == StatusClassSuccess {
		if _, err := w.Write(r.Body); err != nil {
			return err
		}
	}

	return nil
}

// Client is a Gemini client.
type Client struct{}

// Request makes a request for the provided URL. The host is inferred from the URL.
func (c *Client) Request(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// ProxyRequest requests the provided URL from the provided host.
func (c *Client) ProxyRequest(host, url string) (*Response, error) {
	req, err := NewProxyRequest(host, url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do sends a Gemini request and returns a Gemini response.
func (c *Client) Do(req *Request) (*Response, error) {
	// Connect to the host
	conn, err := tls.Dial("tcp", req.Host, &req.TLSConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	// Read the response
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, err
	}

	// Ensure that the response is long enough
	// The minimum response: <STATUS><SPACE><CR><LF> (5 bytes)
	if len(b) < 5 {
		return nil, ErrProtocol
	}

	// Parse the response header
	status, err := strconv.Atoi(string(b[:2]))
	if err != nil {
		return nil, err
	}

	// Read one space
	if b[2] != ' ' {
		return nil, ErrProtocol
	}

	// Find the first <CR><LF>
	i := bytes.Index(b, []byte("\r\n"))
	if i < 3 {
		return nil, ErrProtocol
	}

	// Read the meta
	meta := string(b[3:i])
	if len(meta) > 1024 {
		return nil, ErrProtocol
	}

	// Read the response body
	body := b[i+2:]

	return &Response{
		Status: status,
		Meta:   meta,
		Body:   body,
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

// respond responds to a connection.
func (s *Server) respond(rw net.Conn) {
	var resp *Response

	if rawurl, err := readLine(rw); err != nil {
		resp = &Response{
			Status: StatusBadRequest,
			Meta:   "Bad request",
		}
	} else if len(rawurl) > 1024 {
		resp = &Response{
			Status: StatusBadRequest,
			Meta:   "Requested URL exceeds 1024 bytes",
		}
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error if User is specified in the URL.
		resp = &Response{
			Status: StatusBadRequest,
			Meta:   "Requested URL is invalid",
		}
	} else {
		// Gather information about the request
		req := &Request{
			URL:        url,
			RemoteAddr: rw.RemoteAddr(),
			TLS:        rw.(*tls.Conn).ConnectionState(),
		}
		resp = s.Handler.Serve(req)
	}

	resp.Write(rw)
	rw.Close()
}

// A Handler responds to a Gemini request.
type Handler interface {
	// Serve accepts a Request and returns a Response.
	Serve(*Request) *Response
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
func (m *Mux) HandleFunc(pattern string, handlerFunc func(req *Request) *Response) {
	handler := HandlerFunc(handlerFunc)
	m.Handle(pattern, handler)
}

// Serve responds to the request with the appropriate handler.
func (m *Mux) Serve(req *Request) *Response {
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
type HandlerFunc func(req *Request) *Response

func (f HandlerFunc) Serve(req *Request) *Response {
	return f(req)
}

// readLine reads a line.
func readLine(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return scanner.Text(), nil
}
