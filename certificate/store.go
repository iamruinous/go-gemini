package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A Store maps certificate scopes to certificates.
// It generate certificates as needed and rotates expired certificates.
// The zero value for Store is an empty store ready to use.
//
// Certificate scopes must be registered with Register before certificate
// retrieval; otherwise Get will fail. This prevents the Store from
// creating unnecessary certificates.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	// CreateCertificate, if not nil, is called to create a new certificate
	// to replace a missing or expired certificate. If CreateCertificate
	// is nil, a certificate with a duration of 1 year will be created.
	// The provided scope is suitable for use in a certificate's DNSNames.
	CreateCertificate func(scope string) (tls.Certificate, error)

	certs map[string]tls.Certificate
	path  string
	mu    sync.RWMutex
}

// Register registers the provided scope with the certificate store.
// The scope can either be a hostname or a wildcard pattern (e.g. "*.example.com").
// To accept all hostnames, use the special pattern "*".
func (s *Store) Register(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs == nil {
		s.certs = make(map[string]tls.Certificate)
	}
	s.certs[scope] = tls.Certificate{}
}

// Add adds a certificate with the given scope to the certificate store.
func (s *Store) Add(scope string, cert tls.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs == nil {
		s.certs = make(map[string]tls.Certificate)
	}

	// Parse certificate if not already parsed
	if cert.Leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		cert.Leaf = parsed
	}

	if s.path != "" {
		certPath := filepath.Join(s.path, scope+".crt")
		keyPath := filepath.Join(s.path, scope+".key")
		if err := Write(cert, certPath, keyPath); err != nil {
			return err
		}
	}

	s.certs[scope] = cert
	return nil
}

// Get retrieves a certificate for the given hostname.
// It checks to see if the hostname or a matching pattern has been registered.
// New certificates are generated on demand and expired certificates are
// replaced with new ones.
func (s *Store) Get(hostname string) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certs[hostname]
	if !ok {
		// Try "*"
		cert, ok = s.certs["*"]
	}
	if !ok {
		// Try wildcard
		wildcard := strings.SplitN(hostname, ".", 2)
		if len(wildcard) == 2 {
			hostname = "*." + wildcard[1]
			cert, ok = s.certs[hostname]
		}
	}
	if !ok {
		return nil, errors.New("unrecognized scope")
	}

	// If the certificate is empty or expired, generate a new one.
	if cert.Leaf == nil || cert.Leaf.NotAfter.Before(time.Now()) {
		var err error
		cert, err = s.createCertificate(hostname)
		if err != nil {
			return nil, err
		}
		if err := s.Add(hostname, cert); err != nil {
			return nil, fmt.Errorf("failed to add certificate for %s: %w", hostname, err)
		}
	}

	return &cert, nil
}

func (s *Store) createCertificate(scope string) (tls.Certificate, error) {
	if s.CreateCertificate != nil {
		return s.CreateCertificate(scope)
	}
	return Create(CreateOptions{
		DNSNames: []string{scope},
		Subject: pkix.Name{
			CommonName: scope,
		},
		Duration: 365 * 24 * time.Hour,
	})
}

// Load loads certificates from the provided path.
// New certificates will be written to this path.
// Certificates with scopes that have not been registered will be ignored.
//
// The path should lead to a directory containing certificates
// and private keys named "scope.crt" and "scope.key" respectively,
// where "scope" is the scope of the certificate.
func (s *Store) Load(path string) error {
	matches, err := filepath.Glob(filepath.Join(path, "*.crt"))
	if err != nil {
		return err
	}
	for _, crtPath := range matches {
		scope := strings.TrimSuffix(filepath.Base(crtPath), ".crt")
		if _, ok := s.certs[scope]; !ok {
			continue
		}

		keyPath := strings.TrimSuffix(crtPath, ".crt") + ".key"
		cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			continue
		}
		s.Add(scope, cert)
	}
	s.SetPath(path)
	return nil
}

// Entries returns a map of scopes to certificates.
func (s *Store) Entries() map[string]tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	certs := make(map[string]tls.Certificate)
	for key := range s.certs {
		certs[key] = s.certs[key]
	}
	return certs
}

// SetPath sets the path that new certificates will be written to.
func (s *Store) SetPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
}
