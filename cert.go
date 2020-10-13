package gmi

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// CertificateStore maps hostnames to certificates.
// The zero value of CertificateStore is an empty store ready to use.
type CertificateStore struct {
	store map[string]tls.Certificate
}

// Add adds a certificate for the given hostname to the store.
// It tries to parse the certificate if it is not already parsed.
func (c *CertificateStore) Add(hostname string, cert tls.Certificate) {
	if c.store == nil {
		c.store = map[string]tls.Certificate{}
	}
	// Parse certificate if not already parsed
	if cert.Leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = parsed
		}
	}
	c.store[hostname] = cert
}

// Lookup returns the certificate for the given hostname.
func (c *CertificateStore) Lookup(hostname string) (*tls.Certificate, error) {
	cert, ok := c.store[hostname]
	if !ok {
		return nil, ErrCertificateUnknown
	}
	// Ensure that the certificate is not expired
	if cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()) {
		return &cert, ErrCertificateExpired
	}
	return &cert, nil
}

// Load loads certificates from the given path.
// The path should lead to a directory containing certificates and private keys
// in the form hostname.crt and hostname.key.
// For example, the hostname "localhost" would have the corresponding files
// localhost.crt (certificate) and localhost.key (private key).
func (c *CertificateStore) Load(path string) error {
	matches, err := filepath.Glob(filepath.Join(path, "*.crt"))
	if err != nil {
		return err
	}
	for _, crtPath := range matches {
		keyPath := strings.TrimSuffix(crtPath, ".crt") + ".key"
		cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			continue
		}
		hostname := strings.TrimSuffix(filepath.Base(crtPath), ".crt")
		c.Add(hostname, cert)
	}
	return nil
}

// NewCertificate creates and returns a new parsed certificate.
func NewCertificate(host string, duration time.Duration) (tls.Certificate, error) {
	crt, priv, err := newX509KeyPair(host, duration)
	if err != nil {
		return tls.Certificate{}, err
	}
	var cert tls.Certificate
	cert.Leaf = crt
	cert.Certificate = append(cert.Certificate, crt.Raw)
	cert.PrivateKey = priv
	return cert, nil
}

// newX509KeyPair creates and returns a new certificate and private key.
func newX509KeyPair(host string, duration time.Duration) (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate an ED25519 private key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	public := priv.Public()

	// ED25519 keys should have the DigitalSignature KeyUsage bits set
	// in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, public, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
