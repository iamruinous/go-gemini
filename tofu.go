package gemini

import (
	"bufio"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Trust represents the trustworthiness of a certificate.
type Trust int

const (
	TrustNone   Trust = iota // The certificate is not trusted.
	TrustOnce                // The certificate is trusted once.
	TrustAlways              // The certificate is trusted always.
)

// KnownHosts represents a list of known hosts.
type KnownHosts map[string]Fingerprint

// KnownHostsFile represents a list of known hosts optionally loaded from a file.
// The zero value for KnownHostsFile represents an empty list ready to use.
type KnownHostsFile struct {
	KnownHosts
	out io.Writer
}

// SetOutput sets the output to which new known hosts will be written to.
func (k *KnownHostsFile) SetOutput(w io.Writer) {
	k.out = w
}

// Add adds a known host to the list of known hosts.
func (k *KnownHostsFile) Add(hostname string, fingerprint Fingerprint) {
	if k.KnownHosts == nil {
		k.KnownHosts = KnownHosts{}
	}
	k.KnownHosts[hostname] = fingerprint
}

// Lookup returns the fingerprint of the certificate corresponding to
// the given hostname.
func (k *KnownHostsFile) Lookup(hostname string) (Fingerprint, bool) {
	c, ok := k.KnownHosts[hostname]
	return c, ok
}

// Write writes a known hosts entry to the configured output.
func (k *KnownHostsFile) Write(hostname string, fingerprint Fingerprint) {
	if k.out != nil {
		k.writeKnownHost(k.out, hostname, fingerprint)
	}
}

// WriteAll writes all of the known hosts to the provided io.Writer.
func (k *KnownHostsFile) WriteAll(w io.Writer) error {
	for h, c := range k.KnownHosts {
		if _, err := k.writeKnownHost(w, h, c); err != nil {
			return err
		}
	}
	return nil
}

// writeKnownHost writes a known host to the provided io.Writer.
func (k *KnownHostsFile) writeKnownHost(w io.Writer, hostname string, f Fingerprint) (int, error) {
	return fmt.Fprintf(w, "%s %s %s %d\n", hostname, f.Algorithm, f.Hex, f.Expires)
}

// Load loads the known hosts from the provided path.
// It creates the file if it does not exist.
// New known hosts will be appended to the file.
func (k *KnownHostsFile) Load(path string) error {
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
	k.out = f
	return nil
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid entries are ignored.
func (k *KnownHostsFile) Parse(r io.Reader) {
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
		fingerprint := parts[2]

		expires, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			continue
		}

		k.KnownHosts[hostname] = Fingerprint{
			Algorithm: algorithm,
			Hex:       fingerprint,
			Expires:   expires,
		}
	}
}

// Fingerprint represents a fingerprint using a certain algorithm.
type Fingerprint struct {
	Algorithm string // fingerprint algorithm e.g. SHA-512
	Hex       string // fingerprint in hexadecimal, with ':' between each octet
	Expires   int64  // unix time of the fingerprint expiration date
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
		Expires:   expires.Unix(),
	}
}
