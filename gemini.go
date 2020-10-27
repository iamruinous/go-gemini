package gemini

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

// Status codes.
type Status int

const (
	StatusInput                    Status = 10
	StatusSensitiveInput           Status = 11
	StatusSuccess                  Status = 20
	StatusRedirect                 Status = 30
	StatusRedirectPermanent        Status = 31
	StatusTemporaryFailure         Status = 40
	StatusServerUnavailable        Status = 41
	StatusCGIError                 Status = 42
	StatusProxyError               Status = 43
	StatusSlowDown                 Status = 44
	StatusPermanentFailure         Status = 50
	StatusNotFound                 Status = 51
	StatusGone                     Status = 52
	StatusProxyRequestRefused      Status = 53
	StatusBadRequest               Status = 59
	StatusCertificateRequired      Status = 60
	StatusCertificateNotAuthorized Status = 61
	StatusCertificateNotValid      Status = 62
)

// Class returns the status class for this status code.
func (s Status) Class() StatusClass {
	return StatusClass(s / 10)
}

// StatusMessage returns the status message corresponding to the provided
// status code.
// StatusMessage returns an empty string for input, successs, and redirect
// status codes.
func (s Status) Message() string {
	switch s {
	case StatusTemporaryFailure:
		return "TemporaryFailure"
	case StatusServerUnavailable:
		return "Server unavailable"
	case StatusCGIError:
		return "CGI error"
	case StatusProxyError:
		return "Proxy error"
	case StatusSlowDown:
		return "Slow down"
	case StatusPermanentFailure:
		return "PermanentFailure"
	case StatusNotFound:
		return "Not found"
	case StatusGone:
		return "Gone"
	case StatusProxyRequestRefused:
		return "Proxy request refused"
	case StatusBadRequest:
		return "Bad request"
	case StatusCertificateRequired:
		return "Certificate required"
	case StatusCertificateNotAuthorized:
		return "Certificate not authorized"
	case StatusCertificateNotValid:
		return "Certificate not valid"
	}
	return ""
}

// Status code categories.
type StatusClass int

const (
	StatusClassInput               StatusClass = 1
	StatusClassSuccess             StatusClass = 2
	StatusClassRedirect            StatusClass = 3
	StatusClassTemporaryFailure    StatusClass = 4
	StatusClassPermanentFailure    StatusClass = 5
	StatusClassCertificateRequired StatusClass = 6
)

// Errors.
var (
	ErrInvalidURL            = errors.New("gemini: invalid URL")
	ErrInvalidResponse       = errors.New("gemini: invalid response")
	ErrCertificateUnknown    = errors.New("gemini: unknown certificate")
	ErrCertificateExpired    = errors.New("gemini: certificate expired")
	ErrCertificateNotTrusted = errors.New("gemini: certificate is not trusted")
	ErrNotAFile              = errors.New("gemini: not a file")
	ErrBodyNotAllowed        = errors.New("gemini: response status code does not allow for body")
)

// DefaultClient is the default client. It is used by Send.
//
// On the first request, DefaultClient will load the default list of known hosts.
var DefaultClient Client

var (
	crlf = []byte("\r\n")
)

func init() {
	DefaultClient.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *KnownHosts) error {
		// Load the hosts only once. This is so that the hosts don't have to be loaded
		// for those using their own clients.
		setupDefaultClientOnce.Do(setupDefaultClient)
		return knownHosts.Lookup(hostname, cert)
	}
	DefaultClient.GetCertificate = func(hostname string, store *CertificateStore) *tls.Certificate {
		// If the certificate is in the store, return it
		if cert, err := store.Lookup(hostname); err == nil {
			return cert
		}
		// Otherwise, generate a certificate
		duration := time.Hour
		cert, err := NewCertificate(hostname, duration)
		if err != nil {
			return nil
		}
		// Store and return the certificate
		store.Add(hostname, cert)
		return &cert
	}
}

var setupDefaultClientOnce sync.Once

func setupDefaultClient() {
	DefaultClient.KnownHosts.LoadDefault()
}

// Send sends a Gemini request and returns a Gemini response.
//
// Send is a wrapper around DefaultClient.Send.
func Send(req *Request) (*Response, error) {
	return DefaultClient.Send(req)
}
