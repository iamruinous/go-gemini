package gemini

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// KnownHosts represents a list of known hosts.
type KnownHosts struct {
	hosts []KnownHost
	file  *os.File
}

// LoadKnownHosts loads the known hosts from the provided path.
// It creates the path and any of its parent directories if they do not exist.
// The returned KnownHosts appends to the file whenever a certificate is added.
func LoadKnownHosts(path string) (*KnownHosts, error) {
	if dir := filepath.Dir(path); dir != "." {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	k := &KnownHosts{}
	k.Parse(f)
	f.Close()
	// Open the file for append-only use
	f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	k.file = f
	return k, nil
}

// Add adds a certificate to the KnownHosts.
// If KnownHosts was loaded from a file, Add will append to the file.
func (k *KnownHosts) Add(cert *x509.Certificate) {
	host := NewKnownHost(cert)
	k.hosts = append(k.hosts, host)
	// Append to the file
	if k.file != nil {
		host.Write(k.file)
	}
}

// Lookup looks for the provided certificate in the list of known hosts.
// If the hostname is in the list, but the fingerprint differs,
// Lookup returns ErrCertificateNotTrusted.
// If the hostname is not in the list, Lookup returns ErrCertificateUnknown.
// If the certificate is found and the fingerprint matches, error will be nil.
func (k *KnownHosts) Lookup(cert *x509.Certificate) error {
	now := time.Now().Unix()
	hostname := cert.Subject.CommonName
	fingerprint := Fingerprint(cert)
	for i := range k.hosts {
		if k.hosts[i].Hostname != hostname {
			continue
		}
		if k.hosts[i].Expires <= now {
			// Certificate is expired
			continue
		}
		if k.hosts[i].Fingerprint == fingerprint {
			// Fingerprint matches
			return nil
		}
		// Fingerprint does not match
		return ErrCertificateNotTrusted
	}
	return ErrCertificateUnknown
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid lines are ignored.
func (k *KnownHosts) Parse(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()

		parts := strings.Split(text, " ")
		if len(parts) < 4 {
			continue
		}

		hostname := parts[0]
		algorithm := parts[1]
		fingerprint := parts[2]
		expires, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			continue
		}

		k.hosts = append(k.hosts, KnownHost{
			Hostname:    hostname,
			Algorithm:   algorithm,
			Fingerprint: fingerprint,
			Expires:     expires,
		})
	}
}

// KnownHost represents a known host.
type KnownHost struct {
	Hostname    string // e.g. gemini.circumlunar.space
	Algorithm   string // fingerprint algorithm e.g. SHA-512
	Fingerprint string // fingerprint in hexadecimal, with ':' between each octet
	Expires     int64  // unix time of certificate notAfter date
}

// NewKnownHost creates a new known host from a certificate.
func NewKnownHost(cert *x509.Certificate) KnownHost {
	return KnownHost{
		Hostname:    cert.Subject.CommonName,
		Algorithm:   "SHA-512",
		Fingerprint: Fingerprint(cert),
		Expires:     cert.NotAfter.Unix(),
	}
}

// Write writes the known host to the provided io.Writer.
func (k KnownHost) Write(w io.Writer) (int, error) {
	s := fmt.Sprintf("%s %s %s %d\n", k.Hostname, k.Algorithm, k.Fingerprint, k.Expires)
	return w.Write([]byte(s))
}

// Fingerprint returns the SHA-512 fingerprint of the provided certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum512 := sha512.Sum512(cert.Raw)
	var buf bytes.Buffer
	for i, f := range sum512 {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}
