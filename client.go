package gmi

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Client errors.
var (
	ErrInvalidURL            = errors.New("gemini: invalid URL")
	ErrInvalidResponse       = errors.New("gemini: invalid response")
	ErrInvalidCertificate    = errors.New("gemini: invalid certificate")
	ErrUnknownCertificate    = errors.New("gemini: unknown certificate")
	ErrCertificateNotTrusted = errors.New("gemini: certificate is not trusted")
)

// Request represents a Gemini request.
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host specifies the host on which the URL is sought.
	// This field is ignored by the server.
	Host string

	// Certificate specifies the TLS certificate to use for the request.
	// This field is ignored by the server.
	Certificate *tls.Certificate

	// RemoteAddr allows servers and other software to record the network
	// address that sent the request.
	// This field is ignored by the client.
	RemoteAddr net.Addr

	// TLS allows servers and other software to record information about the TLS
	// connection on which the request was recieved.
	// This field is ignored by the client.
	TLS tls.ConnectionState
}

// Hostname returns the request host without the port.
func (r *Request) Hostname() string {
	return hostname(r.Host)
}

// NewRequest returns a new request. The host is inferred from the provided URL.
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

// read reads a Gemini response from the provided buffered reader.
func (resp *Response) read(r *bufio.Reader) error {
	// Read the status
	statusB := make([]byte, 2)
	if _, err := r.Read(statusB); err != nil {
		return err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return err
	}
	resp.Status = status

	// Disregard invalid status codes
	const minStatus, maxStatus = 1, 6
	statusClass := status / 10
	if statusClass < minStatus || statusClass > maxStatus {
		return ErrInvalidResponse
	}

	// Read one space
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != ' ' {
		return ErrInvalidResponse
	}

	// Read the meta
	meta, err := r.ReadString('\r')
	if err != nil {
		return err
	}
	// Trim carriage return
	meta = meta[:len(meta)-1]
	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return ErrInvalidResponse
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != '\n' {
		return ErrInvalidResponse
	}

	// Read response body
	if status/10 == StatusClassSuccess {
		var err error
		resp.Body, err = ioutil.ReadAll(r)
		if err != nil {
			return err
		}
	}
	return nil
}

// Client represents a Gemini client.
type Client struct {
	// KnownHosts is a list of known hosts that the client trusts.
	KnownHosts KnownHosts

	// CertificateStore contains all the certificates that the client has stored.
	CertificateStore *CertificateStore

	// GetCertificate, if not nil, will be called to determine which certificate
	// (if any) should be used for a request.
	GetCertificate func(req *Request, store *CertificateStore) *tls.Certificate

	// TrustCertificate, if not nil, will be called to determine whether the
	// client should trust the given certificate.
	// If error is not nil, the connection will be aborted.
	TrustCertificate func(hostname string, cert *x509.Certificate, knownHosts *KnownHosts) error
}

// Send sends a Gemini request and returns a Gemini response.
func (c *Client) Send(req *Request) (*Response, error) {
	// Connect to the host
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c.GetCertificate != nil {
				if cert := c.GetCertificate(req, c.CertificateStore); cert != nil {
					return cert, nil
				}
			}
			if req.Certificate == nil {
				return &tls.Certificate{}, nil
			}
			return req.Certificate, nil
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Parse the certificate
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			// Check that the certificate is valid for the hostname
			// Use our own implementation of verifyHostname
			if err := verifyHostname(cert, req.Hostname()); err != nil {
				return err
			}
			// Check that the client trusts the certificate
			if c.TrustCertificate == nil {
				if err := c.KnownHosts.Lookup(req.Hostname(), cert); err != nil {
					return err
				}
			} else if err := c.TrustCertificate(req.Hostname(), cert, &c.KnownHosts); err != nil {
				return err
			}
			return nil
		},
	}
	conn, err := tls.Dial("tcp", req.Host, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	w := bufio.NewWriter(conn)
	req.write(w)
	if err := w.Flush(); err != nil {
		return nil, err
	}

	// Read the response
	resp := &Response{}
	r := bufio.NewReader(conn)
	if err := resp.read(r); err != nil {
		return nil, err
	}
	// Store connection information
	resp.TLS = conn.ConnectionState()
	return resp, nil
}

// hostname extracts the host name from a valid host or host:port
func hostname(host string) string {
	i := strings.LastIndexByte(host, ':')
	if i != -1 {
		return host[:i]
	}
	return host
}
