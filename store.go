package gemini

import (
	"crypto/x509"
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
