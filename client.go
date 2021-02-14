package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// A Client is a Gemini client. Its zero value is a usable client.
type Client struct {
	// TrustCertificate is called to determine whether the client
	// should trust the certificate provided by the server.
	// If TrustCertificate is nil, the client will accept any certificate.
	// If the returned error is not nil, the certificate will not be trusted
	// and the request will be aborted.
	//
	// See the tofu submodule for an implementation of trust on first use.
	TrustCertificate func(hostname string, cert *x509.Certificate) error

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time and reading
	// the response body. The timer remains running after
	// Get or Do return and will interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	Timeout time.Duration
}

// Get sends a Gemini request for the given URL.
//
// An error is returned if there was a Gemini protocol error.
// A non-2x status code doesn't cause an error.
//
// If the returned error is nil, the Response will contain a non-nil Body
// which the user is expected to close.
//
// For more control over requests, use NewRequest and Client.Do.
func (c *Client) Get(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do sends a Gemini request and returns a Gemini response, following
// policy as configured on the client.
//
// An error is returned if there was a Gemini protocol error.
// A non-2x status code doesn't cause an error.
//
// If the returned error is nil, the Response will contain a non-nil Body
// which the user is expected to close.
//
// Generally Get will be used instead of Do.
func (c *Client) Do(req *Request) (*Response, error) {
	// Punycode request URL
	if punycode, err := punycodeHost(req.URL.Host); err != nil {
		return nil, err
	} else {
		// Make a copy of the request
		_req := *req
		req = &_req
		_url := *req.URL
		req.URL = &_url

		// Set the host
		req.URL.Host = punycode
	}

	// Extract hostname and punycode it
	hostname, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		return nil, err
	}
	punycode, err := punycodeHostname(hostname)
	if err != nil {
		return nil, err
	}

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
			return c.verifyConnection(hostname, punycode, cs)
		},
		ServerName: punycode,
	}

	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}

	start := time.Now()
	dialer := net.Dialer{
		Timeout: c.Timeout,
	}

	address := net.JoinHostPort(punycode, port)
	netConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(netConn, config)

	// Set connection deadline
	if c.Timeout != 0 {
		err := conn.SetDeadline(start.Add(c.Timeout))
		if err != nil {
			return nil, fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}

	resp, err := c.do(conn, req)
	if err != nil {
		// If we fail to perform the request/response we have
		// to take responsibility for closing the connection.
		_ = conn.Close()

		return nil, err
	}

	// Store connection state
	state := conn.ConnectionState()
	resp.TLS = &state

	return resp, nil
}

func (c *Client) do(conn *tls.Conn, req *Request) (*Response, error) {
	// Write the request
	w := bufio.NewWriter(conn)

	err := req.Write(w)
	if err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	if err := w.Flush(); err != nil {
		return nil, err
	}

	// Read the response
	resp, err := ReadResponse(conn)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) verifyConnection(hostname, punycode string, cs tls.ConnectionState) error {
	cert := cs.PeerCertificates[0]
	// Try punycode and then hostname
	if err := verifyHostname(cert, punycode); err != nil {
		if err := verifyHostname(cert, hostname); err != nil {
			return err
		}
	}
	// Check expiration date
	if !time.Now().Before(cert.NotAfter) {
		return errors.New("gemini: certificate expired")
	}

	// See if the client trusts the certificate
	if c.TrustCertificate != nil {
		return c.TrustCertificate(hostname, cert)
	}
	return nil
}
