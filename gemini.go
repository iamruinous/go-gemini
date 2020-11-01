package gemini

import (
	"errors"
	"sync"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidURL            = errors.New("gemini: invalid URL")
	ErrInvalidResponse       = errors.New("gemini: invalid response")
	ErrCertificateExpired    = errors.New("gemini: certificate expired")
	ErrCertificateNotFound   = errors.New("gemini: certificate not found")
	ErrCertificateNotTrusted = errors.New("gemini: certificate not trusted")
	ErrCertificateRequired   = errors.New("gemini: certificate required")
	ErrNotAFile              = errors.New("gemini: not a file")
	ErrNotAGeminiURL         = errors.New("gemini: not a Gemini URL")
	ErrBodyNotAllowed        = errors.New("gemini: response status code does not allow for body")
	ErrTooManyRedirects      = errors.New("gemini: too many redirects")
	ErrInputRequired         = errors.New("gemini: input required")
)

// defaultClient is the default client. It is used by Get and Do.
var defaultClient Client

// Get performs a Gemini request for the given url.
func Get(url string) (*Response, error) {
	setupDefaultClientOnce()
	return defaultClient.Get(url)
}

// Do performs a Gemini request and returns a Gemini response.
func Do(req *Request) (*Response, error) {
	setupDefaultClientOnce()
	return defaultClient.Do(req)
}

var defaultClientOnce sync.Once

func setupDefaultClientOnce() {
	defaultClientOnce.Do(func() {
		defaultClient.KnownHosts.LoadDefault()
	})
}
