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
)

// Errors.
var (
	ErrInvalidKnownHosts = errors.New("gemini: invalid known hosts")
)

// KnownHost represents a known host.
type KnownHost struct {
	Hostname    string // e.g. gemini.circumlunar.space
	Algorithm   string // fingerprint algorithm
	Fingerprint string // fingerprint in hexadecimal, with ':' between each octet
	NotAfter    int64  // unix time of certificate notAfter date
}

// ParseKnownHosts parses and returns a list of known hosts from the provided io.Reader.
func ParseKnownHosts(r io.Reader) ([]KnownHost, error) {
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
		notAfter, err := strconv.ParseInt(parts[3], 10, 0)
		if err != nil {
			return nil, ErrInvalidKnownHosts
		}

		hosts = append(hosts, KnownHost{
			Hostname:    hostname,
			Algorithm:   algorithm,
			Fingerprint: fingerprint,
			NotAfter:    notAfter,
		})
	}

	return hosts, nil
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
