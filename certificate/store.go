package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store represents a certificate store.
// The zero value for Store is an empty store ready to use.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	// CreateCertificate, if not nil, is called to create a new certificate
	// to replace a missing or expired certificate.
	CreateCertificate func(scope string) (tls.Certificate, error)

	certs map[string]tls.Certificate
	path  string
	mu    sync.RWMutex
}

// Register registers the provided scope in the certificate store.
// The certificate will be created upon calling GetCertificate.
func (s *Store) Register(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs == nil {
		s.certs = make(map[string]tls.Certificate)
	}
	s.certs[scope] = tls.Certificate{}
}

// Add adds a certificate for the given scope to the certificate store.
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
		// Escape slash character
		path := strings.ReplaceAll(scope, "/", ":")
		certPath := filepath.Join(s.path, path+".crt")
		keyPath := filepath.Join(s.path, path+".key")
		if err := Write(cert, certPath, keyPath); err != nil {
			return err
		}
	}

	s.certs[scope] = cert
	return nil
}

// Lookup returns the certificate for the provided scope.
func (s *Store) Lookup(scope string) (tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certs[scope]
	return cert, ok
}

// GetCertificate retrieves the certificate for the given scope.
// If the retrieved certificate is expired or the scope is registered but
// has no certificate, it calls CreateCertificate to create a new certificate.
func (s *Store) GetCertificate(scope string) (*tls.Certificate, error) {
	cert, ok := s.Lookup(scope)
	if !ok {
		// Try wildcard
		wildcard := strings.SplitN(scope, ".", 2)
		if len(wildcard) == 2 {
			cert, ok = s.Lookup("*." + wildcard[1])
		}
	}
	if !ok {
		return nil, errors.New("unrecognized scope")
	}

	// If the certificate is empty or expired, generate a new one.
	// TODO: Add sane defaults for certificate generation
	if cert.Leaf == nil || cert.Leaf.NotAfter.Before(time.Now()) {
		if s.CreateCertificate != nil {
			cert, err := s.CreateCertificate(scope)
			if err != nil {
				return nil, err
			}
			if err := s.Add(scope, cert); err != nil {
				return nil, fmt.Errorf("failed to write new certificate for %s: %w", scope, err)
			}
			return &cert, nil
		}
		return nil, errors.New("no suitable certificate found")
	}

	return &cert, nil
}

// Load loads certificates from the provided path.
// New certificates will be written to this path.
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
		keyPath := strings.TrimSuffix(crtPath, ".crt") + ".key"
		cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			continue
		}
		scope := strings.TrimSuffix(filepath.Base(crtPath), ".crt")
		// Unescape slash character
		scope = strings.ReplaceAll(scope, ":", "/")
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
