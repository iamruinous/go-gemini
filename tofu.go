package gemini

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Errors.
var (
	ErrInvalidKnownHosts = errors.New("gemini: invalid known hosts")
)

// KnownHosts represents a list of known hosts.
type KnownHosts []KnownHost

// Has reports whether the given hostname and certificate are in the list.
func (k KnownHosts) Has(hostname string, cert *x509.Certificate) bool {
	now := time.Now().Unix()
	fingerprint := Fingerprint(cert)
	for i := range k {
		if k[i].Expires < now && k[i].Hostname == hostname && k[i].Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// KnownHost represents a known host.
type KnownHost struct {
	Hostname    string // e.g. gemini.circumlunar.space
	Algorithm   string // fingerprint algorithm e.g. SHA-512
	Fingerprint string // fingerprint in hexadecimal, with ':' between each octet
	Expires     int64  // unix time of certificate notAfter date
}

// ParseKnownHosts parses and returns a list of known hosts from the provided io.Reader.
func ParseKnownHosts(r io.Reader) (KnownHosts, error) {
	hosts := []KnownHost{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()

		parts := strings.Split(text, " ")
		if len(parts) < 4 {
			return nil, ErrInvalidKnownHosts
		}

		hostname := parts[0]
		algorithm := parts[1]
		fingerprint := parts[2]
		expires, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			return nil, ErrInvalidKnownHosts
		}

		hosts = append(hosts, KnownHost{
			Hostname:    hostname,
			Algorithm:   algorithm,
			Fingerprint: fingerprint,
			Expires:     expires,
		})
	}

	return hosts, nil
}

// AppendKnownHost appends the host to the provided io.Writer.
func AppendKnownHost(host KnownHost, w io.Writer) error {
	return nil
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
