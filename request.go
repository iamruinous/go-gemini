package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
)

// A Request represents a Gemini request received by a server or to be sent
// by a client.
//
// The field semantics differ slightly between client and server usage.
// In addition to the notes on the fields below, see the documentation
// for Request.Write and TODO: RoundTripper.
type Request struct {
	// URL specifies the URL being requested (for server
	// requests) or the URL to access (for client requests).
	URL *url.URL

	// For client requests, Host specifies the server to connect to.
	// Host must contain a port.
	// This field is ignored by the Gemini server.
	Host string

	// Certificate specifies the TLS certificate to use for the request.
	//
	// On the server side, if the client provided a certificate then
	// Certificate.Leaf is guaranteed to be non-nil.
	Certificate *tls.Certificate

	// RemoteAddr allows Gemini servers and other software to record
	// the network address that sent the request, usually for
	// logging. This field is not filled in by ReadRequest and
	// has no defined format. The Gemini server in this package
	// sets RemoteAddr to an "IP:port" address before invoking a
	// handler.
	// This field is ignored by the Gemini client.
	RemoteAddr net.Addr

	// TLS allows Gemini servers and other software to record
	// information about the TLS connection on which the request
	// was received. This field is not filled in by ReadRequest.
	// The Gemini server in this package sets the field for
	// TLS-enabled connections before invoking a handler;
	// otherwise it leaves the field nil.
	// This field is ignored by the Gemini client.
	TLS *tls.ConnectionState

	// Context specifies the context to use for client requests.
	// If Context is nil, the background context will be used.
	// This field is ignored by the Gemini server.
	Context context.Context
}

// NewRequest returns a new request. The host is inferred from the URL.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	return NewRequestFromURL(u), nil
}

// NewRequestFromURL returns a new request for the given URL.
// The host is inferred from the URL.
//
// Callers should be careful that the URL query is properly escaped.
// See the documentation for QueryEscape for more information.
func NewRequestFromURL(url *url.URL) *Request {
	host := url.Host
	if url.Port() == "" {
		host += ":1965"
	}
	return &Request{
		URL:  url,
		Host: host,
	}
}

// ReadRequest reads and parses an incoming request from r.
//
// ReadRequest is a low-level function and should only be used
// for specialized applications; most code should use the Server
// to read requests and handle them via the Handler interface.
func ReadRequest(r io.Reader) (*Request, error) {
	// Read URL
	br := bufio.NewReaderSize(r, 1026)
	rawurl, err := br.ReadString('\r')
	if err != nil {
		return nil, err
	}
	// Read terminating line feed
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrInvalidRequest
	}
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Validate URL
	if len(rawurl) > 1024 {
		return nil, ErrInvalidRequest
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		// User is not allowed
		return nil, ErrInvalidURL
	}
	return &Request{URL: u}, nil
}

// Write writes a Gemini request in wire format.
// This method consults the request URL only.
func (r *Request) Write(w *bufio.Writer) error {
	url := r.URL.String()
	// User is invalid
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
