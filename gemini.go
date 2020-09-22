// Package gemini implements the Gemini protocol.
package gemini

import (
	"crypto/tls"
	"errors"
	"io"
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
	ErrProtocol   = errors.New("Protocol error")
	ErrInvalidURL = errors.New("Invalid URL")
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
//     req.Certificates = append(req.Certificates, cert)
//
type Request struct {
	Host         string            // host or host:port
	URL          *url.URL          // the requested URL
	Certificates []tls.Certificate // client certificates
}

// NewRequest returns a new request. The host is inferred from the provided url.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// UserInfo is invalid
	if u.User != nil {
		return nil, ErrInvalidURL
	}

	return &Request{
		Host: u.Host,
		URL:  u,
	}, nil
}

// NewProxyRequest returns a new request using the provided host.
func NewProxyRequest(host, rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// UserInfo is invalid
	if u.User != nil {
		return nil, ErrInvalidURL
	}

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// Write writes the Gemini request to the provided io.Writer.
func (r *Request) Write(w io.Writer) error {
	request := r.URL.String() + "\r\n"
	_, err := w.Write([]byte(request))
	return err
}

// Response is a Gemini response.
type Response struct {
	Status int
	Meta   string
	Body   []byte
}

// Write writes the Gemini response header and body to the provided io.Writer.
func (r *Response) Write(w io.Writer) error {
	header := strconv.Itoa(r.Status) + " " + r.Meta + "\r\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return err
	}

	// Only write the response body on success
	if r.Status/10 == StatusClassSuccess {
		if _, err := w.Write(r.Body); err != nil {
			return err
		}
	}

	return nil
}
