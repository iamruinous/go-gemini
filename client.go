// Package gemini implements the Gemini protocol.
package gemini

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

// Errors.
var (
	ErrProtocol   = errors.New("gemini: protocol error")
	ErrInvalidURL = errors.New("gemini: requested URL is invalid")
)

// Request represents a Gemini request.
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host specifies the host on which the URL is sought.
	// If this field is empty, the host will be inferred from the URL.
	// This field is ignored by the server.
	Host string

	// Certificate specifies the TLS certificate to use for the request.
	Certificate tls.Certificate

	// RemoteAddr allows servers and other software to record the network
	// address that sent the request.
	// This field is ignored by the client.
	RemoteAddr net.Addr

	// TLS allows servers and other software to record information about the TLS
	// connection on which the request was recieved.
	// This field is ignored by the client.
	TLS tls.ConnectionState
}

// NewRequest returns a new request. The host is inferred from the provided url.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	host := u.Host

	// If there is no port, use the default port of 1965
	if u.Port() == "" {
		host += ":1965"
	}

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// NewProxyRequest returns a new request using the provided host.
// The provided host must contain a port.
func NewProxyRequest(host, rawurl string) (*Request, error) {
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

	// Read one space
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != ' ' {
		return ErrProtocol
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
		return ErrProtocol
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != '\n' {
		return ErrProtocol
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
	// VerifyCertificate, if not nil, will be called to verify the server certificate.
	// If error is not nil, the connection will be aborted.
	VerifyCertificate func(cert *x509.Certificate, req *Request) error
}

// Send sends a Gemini request and returns a Gemini response.
func (c *Client) Send(req *Request) (*Response, error) {
	// Connect to the host
	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{req.Certificate},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			return c.VerifyCertificate(cert, req)
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
	// Store connection information
	resp.TLS = conn.ConnectionState()
	if err := resp.read(r); err != nil {
		return nil, err
	}
	return resp, nil
}
