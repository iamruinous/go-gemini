package gemini

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
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

	// DialContext specifies the dial function for creating TCP connections.
	// If DialContext is nil, the client dials using package net.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Get sends a Gemini request for the given URL.
// If the provided context is canceled or times out, the request
// is aborted and the context's error is returned.
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

// Do sends a Gemini request and returns a Gemini response.
// If the provided context is canceled or times out, the request
// is aborted and the context's error is returned.
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
	conn, err := c.dialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
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
		ctx, cancel := context.WithCancel(ctx)
		done := ctx.Done()
		cw := &contextWriter{
			ctx:    ctx,
			done:   done,
			cancel: cancel,
			wc:     conn,
		}
		cr := &contextReader{
			ctx:    ctx,
			done:   done,
			cancel: cancel,
			rc:     conn,
		}

		resp, err := c.do(cw, cr, req)
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

func (c *Client) do(w io.Writer, rc io.ReadCloser, req *Request) (*Response, error) {
	// Write the request
	if err := req.Write(w); err != nil {
		return nil, err
	}

	// Read the response
	resp, err := ReadResponse(rc)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.DialContext != nil {
		return c.DialContext(ctx, network, addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// punycodeHostname returns the punycoded version of hostname.
func punycodeHostname(hostname string) (string, error) {
	if net.ParseIP(hostname) != nil {
		return hostname, nil
	}
	if isASCII(hostname) {
		return hostname, nil
	}
	return idna.Lookup.ToASCII(hostname)
}

type contextReader struct {
	ctx    context.Context
	done   <-chan struct{}
	cancel func()
	rc     io.ReadCloser
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.done:
		r.rc.Close()
		return 0, r.ctx.Err()
	default:
	}
	n, err := r.rc.Read(p)
	if err != nil {
		r.cancel()
	}
	return n, err
}

func (r *contextReader) Close() error {
	r.cancel()
	return r.rc.Close()
}

type contextWriter struct {
	ctx    context.Context
	done   <-chan struct{}
	cancel func()
	wc     io.WriteCloser
}

func (w *contextWriter) Write(b []byte) (int, error) {
	select {
	case <-w.done:
		w.wc.Close()
		return 0, w.ctx.Err()
	default:
	}
	n, err := w.wc.Write(b)
	if err != nil {
		w.cancel()
	}
	return n, err
}

func (w *contextWriter) Close() error {
	w.cancel()
	return w.wc.Close()
}
