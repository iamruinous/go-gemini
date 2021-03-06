package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A Store represents a TLS certificate store.
// The zero value for Store is an empty store ready to use.
//
// Store can be used to store server certificates.
// Servers should provide a hostname or wildcard pattern as a certificate scope.
// Servers will most likely use the methods Register, Load and Get.
//
// Store can also be used to store client certificates.
// Clients should provide the hostname and path of a URL as a certificate scope
// (without a trailing slash).
// Clients will most likely use the methods Add, Load, and Lookup.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	// CreateCertificate, if not nil, is called by Get to create a new
	// certificate to replace a missing or expired certificate.
	// The provided scope is suitable for use in a certificate's DNSNames.
	CreateCertificate func(scope string) (tls.Certificate, error)

	scopes map[string]struct{}
	certs  map[string]tls.Certificate
	path   string
	mu     sync.RWMutex
}

// Register registers the provided scope with the certificate store.
// The scope can either be a hostname or a wildcard pattern (e.g. "*.example.com").
// To accept all hostnames, use the special pattern "*".
//
// Calls to Get will only succeed for registered scopes.
// Other methods are not affected.
func (s *Store) Register(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scopes == nil {
		s.scopes = make(map[string]struct{})
	}
	s.scopes[scope] = struct{}{}
}

// Add registers the certificate for the given scope.
// If a certificate already exists for scope, Add will overwrite it.
func (s *Store) Add(scope string, cert tls.Certificate) error {
	// Parse certificate if not already parsed
	if cert.Leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		cert.Leaf = parsed
	}

	if err := s.write(scope, cert); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certs == nil {
		s.certs = make(map[string]tls.Certificate)
	}
	s.certs[scope] = cert
	return nil
}

func (s *Store) write(scope string, cert tls.Certificate) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.path != "" {
		certPath := filepath.Join(s.path, scope+".crt")
		keyPath := filepath.Join(s.path, scope+".key")

		dir := filepath.Dir(certPath)
		os.MkdirAll(dir, 0755)

		if err := Write(cert, certPath, keyPath); err != nil {
			return err
		}
	}
	return nil
}

// Get retrieves a certificate for the given hostname.
// If no matching scope has been registered, Get returns an error.
// Get generates new certificates as needed and rotates expired certificates.
// It calls CreateCertificate to create a new certificate if it is not nil,
// otherwise it creates certificates with a duration of 100 years.
//
// Get is suitable for use in a gemini.Server's GetCertificate field.
func (s *Store) Get(hostname string) (*tls.Certificate, error) {
	s.mu.RLock()
	_, ok := s.scopes[hostname]
	if !ok {
		// Try wildcard
		wildcard := strings.SplitN(hostname, ".", 2)
		if len(wildcard) == 2 {
			hostname = "*." + wildcard[1]
			_, ok = s.scopes[hostname]
		}
	}
	if !ok {
		// Try "*"
		_, ok = s.scopes["*"]
	}
	if !ok {
		s.mu.RUnlock()
		return nil, errors.New("unrecognized scope")
	}
	cert := s.certs[hostname]
	s.mu.RUnlock()

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

// Lookup returns the certificate for the provided scope.
// Lookup also checks for certificates in parent scopes.
// For example, given the scope "example.com/a/b/c", Lookup will first check
// "example.com/a/b/c", then "example.com/a/b", then "example.com/a", and
// finally "example.com" for a certificate. As a result, a certificate with
// scope "example.com" will match all scopes beginning with "example.com".
func (s *Store) Lookup(scope string) (tls.Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certs[scope]
	if !ok {
		scope = path.Dir(scope)
		for scope != "." {
			cert, ok = s.certs[scope]
			if ok {
				break
			}
			scope = path.Dir(scope)
		}
	}
	return cert, ok
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
		Duration: 100 * 365 * 24 * time.Hour,
	})
}

// Load loads certificates from the provided path.
// New certificates will be written to this path.
// The path should lead to a directory containing certificates
// and private keys named "scope.crt" and "scope.key" respectively,
// where "scope" is the scope of the certificate.
func (s *Store) Load(path string) error {
	matches := findCertificates(path)
	for _, crtPath := range matches {
		keyPath := strings.TrimSuffix(crtPath, ".crt") + ".key"
		cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			continue
		}

		scope := filepath.Clean(crtPath)
		scope = strings.TrimPrefix(crtPath, filepath.Clean(path))
		scope = strings.TrimPrefix(scope, "/")
		scope = strings.TrimSuffix(scope, ".crt")
		s.Add(scope, cert)
	}
	s.SetPath(path)
	return nil
}

func findCertificates(path string) (matches []string) {
	filepath.Walk(path, func(path string, _ fs.FileInfo, err error) error {
		if filepath.Ext(path) == ".crt" {
			matches = append(matches, path)
		}
		return nil
	})
	return
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
