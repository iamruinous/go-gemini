package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

// Client is a Gemini client.
type Client struct {
	// TrustCertificate is called to determine whether the client
	// should trust the certificate provided by the server.
	// If TrustCertificate is nil, the client will accept any certificate.
	// If the returned error is not nil, the certificate will not be trusted
	// and the request will be aborted.
	TrustCertificate func(hostname string, cert *x509.Certificate) error

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time and reading
	// the response body. The timer remains running after
	// Get and Do return and will interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	Timeout time.Duration
}

// Get performs a Gemini request for the given URL.
func (c *Client) Get(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do performs a Gemini request and returns a Gemini response.
func (c *Client) Do(req *Request) (*Response, error) {
	// Extract hostname
	colonPos := strings.LastIndex(req.Host, ":")
	if colonPos == -1 {
		colonPos = len(req.Host)
	}
	hostname := req.Host[:colonPos]

	// Connect to the host
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if req.Certificate != nil {
				return req.Certificate, nil
			}
			return &tls.Certificate{}, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return c.verifyConnection(req, cs)
		},
		ServerName: hostname,
	}
	// Set connection context
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}
	netConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", req.Host)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(netConn, config)
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

	return resp, nil
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

	// See if the client trusts the certificate
	if c.TrustCertificate != nil {
		return c.TrustCertificate(hostname, cert)
	}
	return nil
}
