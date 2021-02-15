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
type Request struct {
	// URL specifies the URL being requested (for server
	// requests) or the URL to access (for client requests).
	URL *url.URL

	// For client requests, Host optionally specifies the server to
	// connect to. It must be of the form "host:port".
	// If empty, the value of URL.Host is used.
	// For international domain names, Host may be in Punycode or
	// Unicode form. Use golang.org/x/net/idna to convert it to
	// either format if needed.
	// This field is ignored by the Gemini server.
	Host string

	// For client requests, Certificate optionally specifies the
	// TLS certificate to present to the other side of the connection.
	// This field is ignored by the Gemini server.
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

	// Context specifies the context to use for outgoing requests.
	// The context controls the entire lifetime of a request and its
	// response: obtaining a connection, sending the request, and
	// reading the response header and body.
	// If Context is nil, the background context will be used.
	// This field is ignored by the Gemini server.
	Context context.Context
}

// NewRequest returns a new request.
//
// The returned Request is suitable for use with Client.Do.
//
// Callers should be careful that the URL query is properly escaped.
// See the documentation for QueryEscape for more information.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	return &Request{URL: u}, nil
}

// ReadRequest reads and parses an incoming request from r.
//
// ReadRequest is a low-level function and should only be used
// for specialized applications; most code should use the Server
// to read requests and handle them via the Handler interface.
func ReadRequest(r io.Reader) (*Request, error) {
	// Read URL
	r = io.LimitReader(r, 1026)
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
	if r.URL.User != nil {
		// User is not allowed
		return ErrInvalidURL
	}
	url := r.URL.String()
	if len(url) > 1024 {
		return ErrInvalidRequest
	}
	if _, err := w.WriteString(url); err != nil {
		return err
	}
	if _, err := w.Write(crlf); err != nil {
		return err
	}
	return nil
}
