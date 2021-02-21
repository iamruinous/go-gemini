package gemini

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
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

	// DialContext specifies the dial function for creating TCP connections.
	// If DialContext is nil, the client dials using package net.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
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
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
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
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if ctx == nil {
		panic("nil context")
	}

	// Punycode request URL host
	host, port := splitHostPort(req.URL.Host)
	punycode, err := punycodeHostname(host)
	if err != nil {
		return nil, err
	}
	if host != punycode {
		host = punycode

		// Copy the URL and update the host
		u := new(url.URL)
		*u = *req.URL
		u.Host = net.JoinHostPort(host, port)

		// Use the new URL in the request so that the server gets
		// the punycoded hostname
		req = &Request{
			URL: u,
		}
	}

	// Use request host if provided
	if req.Host != "" {
		host, port = splitHostPort(req.Host)
		host, err = punycodeHostname(host)
		if err != nil {
			return nil, err
		}
	}

	addr := net.JoinHostPort(host, port)

	// Connect to the host
	start := time.Now()
	conn, err := c.dialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// Set the connection deadline
	if c.Timeout != 0 {
		conn.SetDeadline(start.Add(c.Timeout))
	}

	// Setup TLS
	conn = tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if req.Certificate != nil {
				return req.Certificate, nil
			}
			return &tls.Certificate{}, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return c.verifyConnection(cs, host)
		},
		ServerName: host,
	})

	type result struct {
		resp *Response
		err  error
	}

	res := make(chan result, 1)
	go func() {
		resp, err := c.do(conn, req)
		res <- result{resp, err}
	}()

	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	case r := <-res:
		return r.resp, r.err
	}
}

func (c *Client) do(conn net.Conn, req *Request) (*Response, error) {
	// Write the request
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	// Read the response
	resp, err := ReadResponse(conn)
	if err != nil {
		return nil, err
	}

	// Store TLS connection state
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		resp.TLS = &state
	}

	return resp, nil
}

func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.DialContext != nil {
		return c.DialContext(ctx, network, addr)
	}
	return (&net.Dialer{
		Timeout: c.Timeout,
	}).DialContext(ctx, network, addr)
}

func (c *Client) verifyConnection(cs tls.ConnectionState, hostname string) error {
	cert := cs.PeerCertificates[0]
	// Verify hostname
	if err := verifyHostname(cert, hostname); err != nil {
		return err
	}
	// Check expiration date
	if !time.Now().Before(cert.NotAfter) {
		return ErrCertificateExpired
	}
	// See if the client trusts the certificate
	if c.TrustCertificate != nil {
		return c.TrustCertificate(hostname, cert)
	}
	return nil
}

func splitHostPort(hostport string) (host, port string) {
	var err error
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		// Likely no port
		host = hostport
		port = "1965"
	}
	return
}
