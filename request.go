package gemini

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/url"
)

// A Request represents a Gemini request received by a server or to be sent
// by a client.
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host optionally specifies the server to
	// connect to. It may be of the form "host" or "host:port".
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

	conn net.Conn
	tls  *tls.ConnectionState
}

// NewRequest returns a new request.
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
	return &Request{URL: u}, nil
}

// Write writes a Gemini request in wire format.
// This method consults the request URL only.
func (r *Request) Write(w io.Writer) error {
	bw := bufio.NewWriterSize(w, 1026)
	url := r.URL.String()
	if len(url) > 1024 {
		return ErrInvalidRequest
	}
	if _, err := bw.WriteString(url); err != nil {
		return err
	}
	if _, err := bw.Write(crlf); err != nil {
		return err
	}
	return bw.Flush()
}

// Conn returns the network connection on which the request was received.
func (r *Request) Conn() net.Conn {
	return r.conn
}

// TLS returns information about the TLS connection on which the
// request was received.
func (r *Request) TLS() *tls.ConnectionState {
	if r.tls == nil {
		if tlsConn, ok := r.conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			r.tls = &state
		}
	}
	return r.tls
}
