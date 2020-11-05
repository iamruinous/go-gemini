package gemini

import (
	"errors"
	"sync"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidURL      = errors.New("gemini: invalid URL")
	ErrInvalidResponse = errors.New("gemini: invalid response")
	ErrBodyNotAllowed  = errors.New("gemini: response body not allowed")
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
