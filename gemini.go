package gemini

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidURL            = errors.New("gemini: invalid URL")
	ErrInvalidResponse       = errors.New("gemini: invalid response")
	ErrCertificateUnknown    = errors.New("gemini: unknown certificate")
	ErrCertificateExpired    = errors.New("gemini: certificate expired")
	ErrCertificateNotTrusted = errors.New("gemini: certificate is not trusted")
	ErrNotAFile              = errors.New("gemini: not a file")
	ErrNotAGeminiURL         = errors.New("gemini: not a Gemini URL")
	ErrBodyNotAllowed        = errors.New("gemini: response status code does not allow for body")
	ErrTooManyRedirects      = errors.New("gemini: too many redirects")
	ErrInputRequired         = errors.New("gemini: input required")
	ErrCertificateRequired   = errors.New("gemini: certificate required")
)

// DefaultClient is the default client. It is used by Get and Do.
//
// On the first request, DefaultClient loads the default list of known hosts.
var DefaultClient Client

// Get performs a Gemini request for the given url.
//
// Get is a wrapper around DefaultClient.Get.
func Get(url string) (*Response, error) {
	return DefaultClient.Get(url)
}

// Do performs a Gemini request and returns a Gemini response.
//
// Do is a wrapper around DefaultClient.Do.
func Do(req *Request) (*Response, error) {
	return DefaultClient.Do(req)
}

var defaultClientOnce sync.Once

func init() {
	DefaultClient.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *KnownHosts) error {
		defaultClientOnce.Do(func() { knownHosts.LoadDefault() })
		return knownHosts.Lookup(hostname, cert)
	}
	DefaultClient.GetCertificate = func(req *Request, store *ClientCertificateStore) *tls.Certificate {
		if cert, err := store.Lookup(req.URL.Hostname(), req.URL.Path); err == nil {
			return cert
		}
		duration := time.Hour
		cert, err := NewCertificate("", duration)
		if err != nil {
			return nil
		}
		store.Add(req.URL.Hostname()+req.URL.Path, cert)
		return &cert
	}
}
