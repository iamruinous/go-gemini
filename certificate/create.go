// Package certificate provides utility functions for TLS certificates.
package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// CreateOptions configures the creation of a TLS certificate.
type CreateOptions struct {
	// Subject Alternate Name values.
	// Should contain the DNS names that this certificate is valid for.
	// E.g. example.com, *.example.com
	DNSNames []string

	// Subject Alternate Name values.
	// Should contain the IP addresses that the certificate is valid for.
	IPAddresses []net.IP

	// Subject specifies the certificate Subject.
	//
	// Subject.CommonName can contain the DNS name that this certificate
	// is valid for. Server certificates should specify both a Subject
	// and a Subject Alternate Name.
	Subject pkix.Name

	// Duration specifies the amount of time that the certificate is valid for.
	Duration time.Duration

	// Ed25519 specifies whether to generate an Ed25519 key pair.
	// If false, an ECDSA key will be generated instead.
	// Ed25519 is not as widely supported as ECDSA.
	Ed25519 bool
}

// Create creates a new TLS certificate.
func Create(options CreateOptions) (tls.Certificate, error) {
	crt, priv, err := newX509KeyPair(options)
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
func newX509KeyPair(options CreateOptions) (*x509.Certificate, crypto.PrivateKey, error) {
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	if options.Ed25519 {
		// Generate an Ed25519 private key
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Generate an ECDSA private key
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		priv = private
		pub = &private.PublicKey
	}

	// ECDSA and Ed25519 keys should have the DigitalSignature KeyUsage bits
	// set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(options.Duration)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           options.IPAddresses,
		DNSNames:              options.DNSNames,
		Subject:               options.Subject,
	}

	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// Write writes the provided certificate and its private key
// to certPath and keyPath respectively.
func Write(cert tls.Certificate, certPath, keyPath string) error {
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}
