package gemini

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

	// InsecureSkipTrust specifies whether the client should trust
	// any certificate it receives without checking KnownHosts
	// or calling TrustCertificate.
	// Use with caution.
	InsecureSkipTrust bool

	// GetInput is called to retrieve input when the server requests it.
	// If GetInput is nil or returns false, no input will be sent and
	// the response will be returned.
	GetInput func(prompt string, sensitive bool) (input string, ok bool)

	// CheckRedirect determines whether to follow a redirect.
	// If CheckRedirect is nil, redirects will not be followed.
	CheckRedirect func(req *Request, via []*Request) error

	// CreateCertificate is called to generate a certificate upon
	// the request of a server.
	// If CreateCertificate is nil or the returned error is not nil,
	// the request will not be sent again and the response will be returned.
	CreateCertificate func(hostname, path string) (tls.Certificate, error)

	// TrustCertificate is called to determine whether the client
	// should trust a certificate it has not seen before.
	// If TrustCertificate is nil, the certificate will not be trusted
	// and the connection will be aborted.
	//
	// If TrustCertificate returns TrustOnce, the certificate will be added
	// to the client's list of known hosts.
	// If TrustCertificate returns TrustAlways, the certificate will also be
	// written to the known hosts file.
	TrustCertificate func(hostname string, cert *x509.Certificate) Trust
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
			req.Certificate = &cert
			return c.do(req, via)
		}
		return resp, nil

	case resp.Status.Class() == StatusClassInput:
		if c.GetInput != nil {
			input, ok := c.GetInput(resp.Meta, resp.Status == StatusSensitiveInput)
			if ok {
				req.URL.ForceQuery = true
				req.URL.RawQuery = url.QueryEscape(input)
				return c.do(req, via)
			}
		}
		return resp, nil

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
		if target.Scheme != "" && target.Scheme != "gemini" {
			return resp, nil
		}

		redirect := NewRequestFromURL(target)
		if c.CheckRedirect != nil {
			if err := c.CheckRedirect(redirect, via); err != nil {
				return resp, err
			}
			return c.do(redirect, via)
		}
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
		cert, ok := c.Certificates.Lookup(scope)
		if ok {
			// Ensure that the certificate is not expired
			if cert.Leaf != nil && !time.Now().After(cert.Leaf.NotAfter) {
				// Store the certificate
				req.Certificate = &cert
				return &cert, nil
			}
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
	if c.InsecureSkipTrust {
		return nil
	}

	// Check the known hosts
	knownHost, ok := c.KnownHosts.Lookup(hostname)
	if !ok || time.Now().Unix() >= knownHost.Expires {
		// See if the client trusts the certificate
		if c.TrustCertificate != nil {
			switch c.TrustCertificate(hostname, cert) {
			case TrustOnce:
				c.KnownHosts.AddTemporary(hostname, cert)
				return nil
			case TrustAlways:
				c.KnownHosts.Add(hostname, cert)
				return nil
			}
		}
		return errors.New("gemini: certificate not trusted")
	}

	fingerprint := NewFingerprint(cert)
	if knownHost.Hex == fingerprint.Hex {
		return nil
	}
	return errors.New("gemini: fingerprint does not match")
}
