package gemini

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
)

// Client is a Gemini client.
type Client struct {
	// KnownHosts is a list of known hosts.
	KnownHosts KnownHosts

	// Certificates stores client-side certificates.
	Certificates CertificateStore

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time and reading
	// the response body. The timer remains running after
	// Get and Do return and will interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	Timeout time.Duration

	// GetInput is called to retrieve input when the server requests it.
	// If GetInput is nil or returns false, no input will be sent and
	// the response will be returned.
	GetInput func(prompt string, sensitive bool) (input string, ok bool)

	// CheckRedirect determines whether to follow a redirect.
	// If CheckRedirect is nil, a default policy of no more than 5 consecutive
	// redirects will be enforced.
	CheckRedirect func(req *Request, via []*Request) error

	// CreateCertificate is called to generate a certificate upon
	// the request of a server.
	// If CreateCertificate is nil or the returned error is not nil,
	// the request will not be sent again and the response will be returned.
	CreateCertificate func(hostname, path string) (tls.Certificate, error)

	// TrustCertificate determines whether the client should trust
	// the provided certificate.
	// If the returned error is not nil, the connection will be aborted.
	// If TrustCertificate is nil, the client will check KnownHosts
	// for the certificate.
	TrustCertificate func(hostname string, cert *x509.Certificate, knownHosts *KnownHosts) error
}

// Get performs a Gemini request for the given url.
func (c *Client) Get(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do performs a Gemini request and returns a Gemini response.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req, nil)
}

func (c *Client) do(req *Request, via []*Request) (*Response, error) {
	// Connect to the host
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.getClientCertificate(req)
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return c.verifyConnection(req, cs)
		},
	}
	conn, err := tls.Dial("tcp", req.Host, config)
	if err != nil {
		return nil, err
	}
	// Set connection deadline
	if d := c.Timeout; d != 0 {
		conn.SetDeadline(time.Now().Add(d))
	}

	// Write the request
	w := bufio.NewWriter(conn)
	req.write(w)
	if err := w.Flush(); err != nil {
		return nil, err
	}

	// Read the response
	resp := &Response{}
	if err := resp.read(conn); err != nil {
		return nil, err
	}
	// Store connection state
	resp.TLS = conn.ConnectionState()

	switch {
	case resp.Status == StatusCertificateRequired:
		// Check to see if a certificate was already provided to prevent an infinite loop
		if req.Certificate != nil {
			return resp, nil
		}

		hostname, path := req.URL.Hostname(), strings.TrimSuffix(req.URL.Path, "/")
		if c.CreateCertificate != nil {
			cert, err := c.CreateCertificate(hostname, path)
			if err != nil {
				return resp, err
			}
			c.Certificates.Add(hostname+path, cert)
			return c.do(req, via)
		}
		return resp, ErrCertificateRequired

	case resp.Status.Class() == StatusClassInput:
		if c.GetInput != nil {
			input, ok := c.GetInput(resp.Meta, resp.Status == StatusSensitiveInput)
			if ok {
				req.URL.ForceQuery = true
				req.URL.RawQuery = url.QueryEscape(input)
				return c.do(req, via)
			}
		}
		return resp, ErrInputRequired

	case resp.Status.Class() == StatusClassRedirect:
		if via == nil {
			via = []*Request{}
		}
		via = append(via, req)

		target, err := url.Parse(resp.Meta)
		if err != nil {
			return resp, err
		}
		target = req.URL.ResolveReference(target)
		redirect, err := NewRequestFromURL(target)
		if err != nil {
			return resp, err
		}

		if c.CheckRedirect != nil {
			if err := c.CheckRedirect(redirect, via); err != nil {
				return resp, err
			}
		} else if len(via) > 5 {
			// Default policy of no more than 5 redirects
			return resp, ErrTooManyRedirects
		}
		return c.do(redirect, via)
	}

	resp.Request = req
	return resp, nil
}

func (c *Client) getClientCertificate(req *Request) (*tls.Certificate, error) {
	// Request certificates have the highest precedence
	if req.Certificate != nil {
		return req.Certificate, nil
	}

	// Search recursively for the certificate
	scope := req.URL.Hostname() + strings.TrimSuffix(req.URL.Path, "/")
	for {
		cert, err := c.Certificates.Lookup(scope)
		if err == nil {
			return cert, err
		}
		if err == ErrCertificateExpired {
			break
		}
		scope = path.Dir(scope)
		if scope == "." {
			break
		}
	}

	return &tls.Certificate{}, nil
}

func (c *Client) verifyConnection(req *Request, cs tls.ConnectionState) error {
	// Verify the hostname
	var hostname string
	if host, _, err := net.SplitHostPort(req.Host); err == nil {
		hostname = host
	} else {
		hostname = req.Host
	}
	cert := cs.PeerCertificates[0]
	if err := verifyHostname(cert, hostname); err != nil {
		return err
	}
	// Check that the client trusts the certificate
	var err error
	if c.TrustCertificate != nil {
		return c.TrustCertificate(hostname, cert, &c.KnownHosts)
	} else {
		err = c.KnownHosts.Lookup(hostname, cert)
	}
	return err
}
