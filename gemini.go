package gemini

import (
	"crypto/x509"
	"errors"
	"log"
	"os"
	"path/filepath"
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

var (
	crlf = []byte("\r\n")
)

// TOFUClient is a client that implements Trust-On-First-Use.
type TOFUClient struct {
	// Trusts, if not nil, will be called to determine whether the client should
	// trust the provided certificate.
	Trusts func(cert *x509.Certificate, req *Request) bool
}

func (t *TOFUClient) VerifyCertificate(cert *x509.Certificate, req *Request) error {
	if knownHosts.Has(req.URL.Host, cert) {
		return nil
	}
	if t.Trusts != nil && t.Trusts(cert, req) {
		host := NewKnownHost(cert)
		knownHosts = append(knownHosts, host)
		knownHostsFile, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Print(err)
		}
		if _, err := host.Write(knownHostsFile); err != nil {
			log.Print(err)
		}
		return nil
	}
	return errors.New("gemini: certificate not trusted")
}

var (
	knownHosts     KnownHosts
	knownHostsPath string
	knownHostsFile *os.File
)

func init() {
	configDir, err := os.UserConfigDir()
	knownHostsPath = filepath.Join(configDir, "gemini")
	os.MkdirAll(knownHostsPath, 0755)
	knownHostsPath = filepath.Join(knownHostsPath, "known_hosts")
	knownHostsFile, err = os.OpenFile(knownHostsPath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	knownHosts = ParseKnownHosts(knownHostsFile)
}
