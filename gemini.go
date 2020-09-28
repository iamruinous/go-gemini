// Package gmi implements the Gemini protocol
package gmi

import (
	"crypto/x509"
	"sync"
)

// Status codes.
const (
	StatusInput                    = 10
	StatusSensitiveInput           = 11
	StatusSuccess                  = 20
	StatusRedirect                 = 30
	StatusRedirectPermanent        = 31
	StatusTemporaryFailure         = 40
	StatusServerUnavailable        = 41
	StatusCGIError                 = 42
	StatusProxyError               = 43
	StatusSlowDown                 = 44
	StatusPermanentFailure         = 50
	StatusNotFound                 = 51
	StatusGone                     = 52
	StatusProxyRequestRefused      = 53
	StatusBadRequest               = 59
	StatusCertificateRequired      = 60
	StatusCertificateNotAuthorized = 61
	StatusCertificateNotValid      = 62
)

// Status code categories.
const (
	StatusClassInput               = 1
	StatusClassSuccess             = 2
	StatusClassRedirect            = 3
	StatusClassTemporaryFailure    = 4
	StatusClassPermanentFailure    = 5
	StatusClassCertificateRequired = 6
)

// DefaultClient is the default client. It is used by Send.
//
// On the first request, DefaultClient will load the default list of known hosts.
var DefaultClient *Client

var (
	crlf = []byte("\r\n")
)

func init() {
	DefaultClient = &Client{
		TrustCertificate: func(hostname string, cert *x509.Certificate, knownHosts *KnownHosts) error {
			// Load the hosts only once. This is so that the hosts don't have to be loaded
			// for those using their own clients.
			setupDefaultClientOnce.Do(setupDefaultClient)
			return knownHosts.Lookup(hostname, cert)
		},
	}
}

var setupDefaultClientOnce sync.Once

func setupDefaultClient() {
	DefaultClient.KnownHosts.Load()
}

// Send sends a Gemini request and returns a Gemini response.
//
// Send is a wrapper around DefaultClient.Send.
func Send(req *Request) (*Response, error) {
	return DefaultClient.Send(req)
}
