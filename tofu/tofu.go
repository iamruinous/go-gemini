// Package tofu implements trust on first use using hosts and fingerprints.
package tofu

import (
	"bufio"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KnownHosts maps hosts to fingerprints.
type KnownHosts map[string]Fingerprint

// KnownHostsFile represents a list of known hosts optionally loaded from a file.
// The zero value for KnownHostsFile represents an empty list ready to use.
//
// KnownHostsFile is safe for concurrent use by multiple goroutines.
type KnownHostsFile struct {
	KnownHosts
	out io.Writer
	mu  sync.RWMutex
}

// SetOutput sets the output to which new known hosts will be written to.
func (k *KnownHostsFile) SetOutput(w io.Writer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.out = w
}

// Add adds a known host to the list of known hosts.
func (k *KnownHostsFile) Add(hostname string, fingerprint Fingerprint) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.KnownHosts == nil {
		k.KnownHosts = KnownHosts{}
	}
	k.KnownHosts[hostname] = fingerprint
}

// Lookup returns the fingerprint of the certificate corresponding to
// the given hostname.
func (k *KnownHostsFile) Lookup(hostname string) (Fingerprint, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c, ok := k.KnownHosts[hostname]
	return c, ok
}

// Write writes a known hosts entry to the configured output.
func (k *KnownHostsFile) Write(hostname string, fingerprint Fingerprint) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.out != nil {
		_, err := k.writeKnownHost(k.out, hostname, fingerprint)
		if err != nil {
			return fmt.Errorf("failed to write to known host file: %w", err)
		}
	}

	return nil
}

// WriteAll writes all of the known hosts to the provided io.Writer.
func (k *KnownHostsFile) WriteAll(w io.Writer) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for h, c := range k.KnownHosts {
		if _, err := k.writeKnownHost(w, h, c); err != nil {
			return err
		}
	}
	return nil
}

// writeKnownHost writes a known host to the provided io.Writer.
func (k *KnownHostsFile) writeKnownHost(w io.Writer, hostname string, f Fingerprint) (int, error) {
	return fmt.Fprintf(w, "%s %s %s %d\n", hostname, f.Algorithm, f.Hex, f.Expires.Unix())
}

// Load loads the known hosts from the provided path.
// It creates the file if it does not exist.
// New known hosts will be appended to the file.
func (k *KnownHostsFile) Load(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	k.Parse(f)
	k.SetOutput(f)
	return nil
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid entries are ignored.
func (k *KnownHostsFile) Parse(r io.Reader) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.KnownHosts == nil {
		k.KnownHosts = map[string]Fingerprint{}
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()
		parts := strings.Split(text, " ")
		if len(parts) < 4 {
			continue
		}

		hostname := parts[0]
		algorithm := parts[1]
		if algorithm != "SHA-512" {
			continue
		}
		hex := parts[2]

		unix, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			continue
		}
		expires := time.Unix(unix, 0)

		k.KnownHosts[hostname] = Fingerprint{
			Algorithm: algorithm,
			Hex:       hex,
			Expires:   expires,
		}
	}
}

// Fingerprint represents a fingerprint using a certain algorithm.
type Fingerprint struct {
	Algorithm string    // fingerprint algorithm e.g. SHA-512
	Hex       string    // fingerprint in hexadecimal, with ':' between each octet
	Expires   time.Time // unix time of the fingerprint expiration date
}

// NewFingerprint returns the SHA-512 fingerprint of the provided raw data.
func NewFingerprint(raw []byte, expires time.Time) Fingerprint {
	sum512 := sha512.Sum512(raw)
	var b strings.Builder
	for i, f := range sum512 {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", f)
	}
	return Fingerprint{
		Algorithm: "SHA-512",
		Hex:       b.String(),
		Expires:   expires,
	}
}
