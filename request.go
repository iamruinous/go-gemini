package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/url"
)

// Request represents a Gemini request.
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host specifies the host on which the URL is sought.
	// Host must contain a port.
	// This field is ignored by the server.
	Host string

	// Certificate specifies the TLS certificate to use for the request.
	// Request certificates take precedence over client certificates.
	//
	// On the server side, if the client provided a certificate then
	// Certificate.Leaf is guaranteed to be non-nil.
	Certificate *tls.Certificate

	// RemoteAddr allows servers and other software to record the network
	// address that sent the request.
	// This field is ignored by the client.
	RemoteAddr net.Addr

	// TLS allows servers and other software to record information about the TLS
	// connection on which the request was received.
	// This field is ignored by the client.
	TLS tls.ConnectionState

	// Context specifies the context to use for client requests.
	// If Context is nil, the background context will be used.
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

// Write writes the Gemini request to the provided buffered writer.
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
