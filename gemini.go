// Package gemini implements the Gemini protocol.
package gemini

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net"
	"net/url"
	"strconv"
)

// Status codes.
const (
	StatusInput                     = 10
	StatusSensitiveInput            = 11
	StatusSuccess                   = 20
	StatusRedirectTemporary         = 30
	StatusRedirectPermanent         = 31
	StatusTemporaryFailure          = 40
	StatusServerUnavailable         = 41
	StatusCGIError                  = 42
	StatusProxyError                = 43
	StatusSlowDown                  = 44
	StatusPermanentFailure          = 50
	StatusNotFound                  = 51
	StatusGone                      = 52
	StatusProxyRequestRefused       = 53
	StatusBadRequest                = 59
	StatusClientCertificateRequired = 60
	StatusCertificateNotAuthorised  = 61
	StatusCertificateNotValid       = 62
)

// Status code categories.
const (
	StatusClassInput                     = 1
	StatusClassSuccess                   = 2
	StatusClassRedirect                  = 3
	StatusClassTemporaryFailure          = 4
	StatusClassPermanentFailure          = 5
	StatusClassClientCertificateRequired = 6
)

// Errors.
var (
	ErrProtocol       = errors.New("gemini: protocol error")
	ErrInvalidURL     = errors.New("gemini: requested URL is invalid")
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow for body")
)

var (
	crlf = []byte("\r\n")
)

// Request is a Gemini request.
//
// A Request can optionally be configured with a client certificate. Example:
//
//     req := NewRequest(url)
//     cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
//     if err != nil {
//         panic(err)
//     }
//     req.TLSConfig.Certificates = append(req.TLSConfig.Certificates, cert)
//
type Request struct {
	// URL specifies the URL being requested.
	URL *url.URL

	// For client requests, Host specifies the host on which the URL is sought.
	// If this field is empty, the host will be inferred from the URL.
	// This field is ignored by the server.
	Host string

	// The certificate to use for the request.
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

// Do sends a Gemini request and returns a Gemini response.
func Do(req *Request) (*Response, error) {
	// Connect to the host
	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{req.Certificate},
	}
	conn, err := tls.Dial("tcp", req.Host, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	// TODO: Is buffered I/O necessary here?
	w := bufio.NewWriter(conn)
	req.write(w)
	if err := w.Flush(); err != nil {
		return nil, err
	}

	// Read the response status
	r := bufio.NewReader(conn)
	statusB := make([]byte, 2)
	if _, err := r.Read(statusB); err != nil {
		return nil, err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return nil, err
	}

	// Read one space
	if b, err := r.ReadByte(); err != nil {
		return nil, err
	} else if b != ' ' {
		return nil, ErrProtocol
	}

	// Read the meta
	meta, err := r.ReadString('\r')
	if err != nil {
		return nil, err
	}

	// Read terminating newline
	if b, err := r.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrProtocol
	}

	// Trim carriage return
	meta = meta[:len(meta)-1]

	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return nil, ErrProtocol
	}

	// Read response body
	var body []byte
	if status/10 == StatusClassSuccess {
		var err error
		body, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}

	return &Response{
		Status: status,
		Meta:   meta,
		Body:   body,
		TLS:    conn.ConnectionState(),
	}, nil
}
