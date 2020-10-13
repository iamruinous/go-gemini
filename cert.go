package gmi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
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
		return nil, ErrUnknownCertificate
	}
	// Ensure that the certificate is not expired
	if cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()) {
		return &cert, ErrInvalidCertificate
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
	crt, key, err := NewRawCertificate(host, duration)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(crt, key)
}

// NewRawCertificate creates and returns a raw certificate for the given host.
// It generates a self-signed TLS certificate and a ED25519 private key.
func NewRawCertificate(host string, duration time.Duration) (crt, key []byte, err error) {
	// Generate a ED25519 private key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	public := priv.Public().(ed25519.PublicKey)

	// ED25519 keys should have the DigitalSignature KeyUsage bits set
	// in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	// Generate the serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

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

	// Create the certificate
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, public, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode the certificate
	var b bytes.Buffer
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return nil, nil, err
	}
	crt = b.Bytes()

	// Encode the key
	b = bytes.Buffer{}
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, err
	}
	key = b.Bytes()

	return
}

// WriteX509KeyPair writes the provided certificate and private key
// to path.crt and path.key respectively.
func WriteX509KeyPair(path string, crt, key []byte) error {
	// Write the certificate
	crtPath := path + ".crt"
	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := crtOut.Write(crt); err != nil {
		return err
	}

	// Write the private key
	keyPath := path + ".key"
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := keyOut.Write(key); err != nil {
		return err
	}
	return nil
}
