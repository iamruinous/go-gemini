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
)

// Client errors.
var (
	ErrInvalidURL            = errors.New("gemini: invalid URL")
	ErrInvalidResponse       = errors.New("gemini: invalid response")
	ErrCertificateUnknown    = errors.New("gemini: unknown certificate")
	ErrCertificateNotTrusted = errors.New("gemini: certificate is not trusted")
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
	// connection on which the request was recieved.
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

	// CertificateStore maps hostnames to certificates.
	// It is used to determine which certificate to use when the server requests
	// a certificate.
	CertificateStore CertificateStore

	// GetCertificate, if not nil, will be called when a server requests a certificate.
	// The returned certificate will be used when sending the request again.
	// If the certificate is nil, the request will not be sent again and
	// the response will be returned.
	GetCertificate func(hostname string, store *CertificateStore) *tls.Certificate

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
			// Request certificates take precedence over client certificates
			if req.Certificate != nil {
				return req.Certificate, nil
			}
			// If we have already stored the certificate, return it
			if cert, err := c.CertificateStore.Lookup(hostname(req.Host)); err == nil {
				return cert, nil
			}
			return &tls.Certificate{}, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			cert := cs.PeerCertificates[0]
			// Verify the hostname
			if err := verifyHostname(cert, hostname(req.Host)); err != nil {
				return err
			}
			// Check that the client trusts the certificate
			if c.TrustCertificate == nil {
				if err := c.KnownHosts.Lookup(hostname(req.Host), cert); err != nil {
					return err
				}
			} else if err := c.TrustCertificate(hostname(req.Host), cert, &c.KnownHosts); err != nil {
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

	// Resend the request with a certificate if the server responded
	// with CertificateRequired
	if resp.Status == StatusCertificateRequired {
		// Check to see if a certificate was already provided to prevent an infinite loop
		if req.Certificate != nil {
			return resp, nil
		}
		if c.GetCertificate != nil {
			if cert := c.GetCertificate(hostname(req.Host), &c.CertificateStore); cert != nil {
				req.Certificate = cert
				return c.Send(req)
			}
		}
	}
	return resp, nil
}
