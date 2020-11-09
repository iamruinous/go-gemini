package gemini

import (
	"bufio"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Trust represents the trustworthiness of a certificate.
type Trust int

const (
	TrustNone   Trust = iota // The certificate is not trusted.
	TrustOnce                // The certificate is trusted once.
	TrustAlways              // The certificate is trusted always.
)

// KnownHosts represents a list of known hosts.
// The zero value for KnownHosts is an empty list ready to use.
type KnownHosts struct {
	hosts map[string]Fingerprint
	file  *os.File
}

// Load loads the known hosts from the provided path.
// New known hosts will be appended to the file.
func (k *KnownHosts) Load(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	k.Parse(f)
	f.Close()
	// Open the file for append-only use
	f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	k.file = f
	return nil
}

// Add adds a certificate to the list of known hosts.
// If KnownHosts was loaded from a file, Add will append to the file.
func (k *KnownHosts) Add(hostname string, cert *x509.Certificate) {
	k.add(hostname, cert, true)
}

func (k *KnownHosts) add(hostname string, cert *x509.Certificate, write bool) {
	if k.hosts == nil {
		k.hosts = map[string]Fingerprint{}
	}
	fingerprint := NewFingerprint(cert)
	k.hosts[hostname] = fingerprint
	// Append to the file
	if write && k.file != nil {
		appendKnownHost(k.file, hostname, fingerprint)
	}
}

// Lookup returns the fingerprint of the certificate corresponding to
// the given hostname.
func (k *KnownHosts) Lookup(hostname string) (Fingerprint, bool) {
	c, ok := k.hosts[hostname]
	return c, ok
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid lines are ignored.
func (k *KnownHosts) Parse(r io.Reader) {
	if k.hosts == nil {
		k.hosts = map[string]Fingerprint{}
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
		fingerprint := parts[2]

		expires, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			continue
		}

		k.hosts[hostname] = Fingerprint{
			Algorithm: algorithm,
			Hex:       fingerprint,
			Expires:   expires,
		}
	}
}

// Write writes the known hosts to the provided io.Writer.
func (k *KnownHosts) Write(w io.Writer) {
	for h, c := range k.hosts {
		appendKnownHost(w, h, c)
	}
}

func appendKnownHost(w io.Writer, hostname string, f Fingerprint) (int, error) {
	return fmt.Fprintf(w, "%s %s %s %d\n", hostname, f.Algorithm, f.Hex, f.Expires)
}

// Fingerprint represents a fingerprint using a certain algorithm.
type Fingerprint struct {
	Algorithm string // fingerprint algorithm e.g. SHA-512
	Hex       string // fingerprint in hexadecimal, with ':' between each octet
	Expires   int64  // unix time of the fingerprint expiration date
}

// NewFingerprint returns the SHA-512 fingerprint of the provided certificate.
func NewFingerprint(cert *x509.Certificate) Fingerprint {
	sum512 := sha512.Sum512(cert.Raw)
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
		Expires:   cert.NotAfter.Unix(),
	}
}
