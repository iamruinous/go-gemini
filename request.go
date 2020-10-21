package gmi

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

// hostname returns the host without the port.
func hostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}

// NewRequest returns a new request. The host is inferred from the provided URL.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// If there is no port, use the default port of 1965
	host := u.Host
	if u.Port() == "" {
		host += ":1965"
	}

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// NewRequestTo returns a new request for the provided URL to the provided host.
// The host must contain a port.
func NewRequestTo(rawurl, host string) (*Request, error) {
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
