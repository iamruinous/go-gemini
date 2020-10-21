package gmi

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
)

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
