package gemini

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertificateStore maps hostnames to certificates.
type CertificateStore struct {
	store map[string]*x509.Certificate // map of hostnames to certificates
}

func NewCertificateStore() *CertificateStore {
	return &CertificateStore{
		store: map[string]*x509.Certificate{},
	}
}

func (c *CertificateStore) Put(hostname string, cert *x509.Certificate) {
	c.store[hostname] = cert
}

func (c *CertificateStore) Get(hostname string) *x509.Certificate {
	return c.store[hostname]
}

// NewCertificate creates and returns a raw certificate for the given host.
// It generates a self-signed TLS certificate and a ED25519 private key.
func NewCertificate(host string) (crt, key []byte, err error) {
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
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

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

// WriteCertificate writes the provided certificate and private key to name.crt + name.key
func WriteCertificate(name string, crt, key []byte) error {
	// Write the certificate
	crtPath := name + ".crt"
	crtOut, err := os.OpenFile(crtPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := crtOut.Write(crt); err != nil {
		return err
	}

	// Write the private key
	keyPath := name + ".key"
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := keyOut.Write(key); err != nil {
		return err
	}
	return nil
}