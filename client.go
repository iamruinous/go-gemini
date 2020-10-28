package gemini

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
)

// Client represents a Gemini client.
type Client struct {
	// KnownHosts is a list of known hosts that the client trusts.
	KnownHosts KnownHosts

	// CertificateStore maps hostnames to certificates.
	// It is used to determine which certificate to use when the server requests
	// a certificate.
	CertificateStore ClientCertificateStore

	// CheckRedirect, if not nil, will be called to determine whether
	// to follow a redirect.
	// If CheckRedirect is nil, a default policy of no more than 5 consecutive
	// redirects will be enforced.
	CheckRedirect func(req *Request, via []*Request) error

	// GetInput, if not nil, will be called to retrieve input when the server
	// requests it.
	GetInput func(prompt string, sensitive bool) (string, bool)

	// GetCertificate, if not nil, will be called when a server requests a certificate.
	// The returned certificate will be used when sending the request again.
	// If the certificate is nil, the request will not be sent again and
	// the response will be returned.
	GetCertificate func(req *Request, store *ClientCertificateStore) *tls.Certificate

	// TrustCertificate, if not nil, will be called to determine whether the
	// client should trust the given certificate.
	// If error is not nil, the connection will be aborted.
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
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Request certificates take precedence over client certificates
			if req.Certificate != nil {
				return req.Certificate, nil
			}
			// If we have already stored the certificate, return it
			if cert, err := c.CertificateStore.Lookup(hostname(req.Host), req.URL.Path); err == nil {
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
			if cert := c.GetCertificate(req, &c.CertificateStore); cert != nil {
				req.Certificate = cert
				return c.Do(req)
			}
		}
	} else if resp.Status.Class() == StatusClassRedirect {
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
	} else if resp.Status.Class() == StatusClassInput {
		if c.GetInput != nil {
			input, ok := c.GetInput(resp.Meta, resp.Status == StatusSensitiveInput)
			if ok {
				req.URL.ForceQuery = true
				req.URL.RawQuery = url.QueryEscape(input)
				return c.do(req, via)
			}
		}
	}

	resp.Request = req
	return resp, nil
}

// hostname returns the host without the port.
func hostname(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return hostname
}
