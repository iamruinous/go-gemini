package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
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

	// GetInput is called to retrieve input when the server requests it.
	// If GetInput is nil or returns false, no input will be sent and
	// the response will be returned.
	GetInput func(prompt string, sensitive bool) (input string, ok bool)

	// CheckRedirect determines whether to follow a redirect.
	// If CheckRedirect is nil, redirects will not be followed.
	CheckRedirect func(req *Request, via []*Request) error

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
	return c.do(req, nil)
}

func (c *Client) do(req *Request, via []*Request) (*Response, error) {
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
	resp.Request = req
	// Store connection state
	resp.TLS = conn.ConnectionState()

	switch {
	case resp.Status.Class() == StatusClassInput:
		if c.GetInput == nil {
			break
		}

		input, ok := c.GetInput(resp.Meta, resp.Status == StatusSensitiveInput)
		if ok {
			req.URL.ForceQuery = true
			req.URL.RawQuery = QueryEscape(input)
			return c.do(req, via)
		}

	case resp.Status.Class() == StatusClassRedirect:
		if c.CheckRedirect == nil {
			break
		}

		if via == nil {
			via = []*Request{}
		}
		via = append(via, req)

		target, err := url.Parse(resp.Meta)
		if err != nil {
			return resp, err
		}
		target = req.URL.ResolveReference(target)

		redirect := NewRequestFromURL(target)
		redirect.Context = req.Context
		if err := c.CheckRedirect(redirect, via); err != nil {
			return resp, err
		}
		return c.do(redirect, via)
	}

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
