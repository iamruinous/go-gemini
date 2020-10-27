package gemini

import (
	"bufio"
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
	// This field is ignored by the server.
	Certificate *tls.Certificate

	// RemoteAddr allows servers and other software to record the network
	// address that sent the request.
	// This field is ignored by the client.
	RemoteAddr net.Addr

	// TLS allows servers and other software to record information about the TLS
	// connection on which the request was received.
	// This field is ignored by the client.
	TLS tls.ConnectionState
}

// NewRequest returns a new request. The host is inferred from the URL.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	return NewRequestFromURL(u)
}

// NewRequestFromURL returns a new request for the given URL.
// The host is inferred from the URL.
func NewRequestFromURL(url *url.URL) (*Request, error) {
	host := url.Host
	if url.Port() == "" {
		host += ":1965"
	}
	return &Request{
		URL:  url,
		Host: host,
	}, nil
}

// write writes the Gemini request to the provided buffered writer.
func (r *Request) write(w *bufio.Writer) error {
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
