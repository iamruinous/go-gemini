// Package tofu implements trust on first use using hosts and fingerprints.
package tofu

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KnownHostsFile represents a list of known hosts optionally loaded from a file.
// The zero value for KnownHostsFile represents an empty list ready to use.
//
// KnownHostsFile is safe for concurrent use by multiple goroutines.
type KnownHostsFile struct {
	hosts  map[string]KnownHost
	out    *bufio.Writer
	closer io.Closer
	mu     sync.RWMutex
}

// SetOutput sets the output to which new known hosts will be written to.
func (k *KnownHostsFile) SetOutput(w io.WriteCloser) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.out != nil {
		err := k.closer.Close()
		if err != nil {
			return fmt.Errorf("failed to close previous output: %w", err)
		}
	}

	k.out = bufio.NewWriter(w)
	k.closer = w

	return nil
}

// Close closes the output.
func (k *KnownHostsFile) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.out == nil {
		return nil
	}

	err := k.closer.Close()
	if err != nil {
		return err
	}

	k.out = nil
	k.closer = nil

	return nil
}

// Add adds a known host to the list of known hosts.
func (k *KnownHostsFile) Add(h KnownHost) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hosts == nil {
		k.hosts = map[string]KnownHost{}
	}

	k.hosts[h.Hostname] = h

	if k.out != nil {
		h.WriteTo(k.out)
		k.out.WriteRune('\n')

		if err := k.out.Flush(); err != nil {
			return fmt.Errorf("failed to write to known host file: %w", err)
		}
	}

	return nil
}

// Lookup returns the fingerprint of the certificate corresponding to
// the given hostname.
func (k *KnownHostsFile) Lookup(hostname string) (KnownHost, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c, ok := k.hosts[hostname]
	return c, ok
}

// WriteAll writes all of the known hosts to the provided io.Writer.
func (k *KnownHostsFile) WriteTo(w io.Writer) (int64, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	bw := bufio.NewWriter(w)

	var written int64

	for _, h := range k.hosts {
		n, err := h.WriteTo(bw)
		if err != nil {
			return written, err
		}

		bw.WriteByte('\n')
		written += n + 1
	}

	return written, bw.Flush()
}

// Open loads the known hosts from the provided path.
// It creates the file if it does not exist.
// New known hosts will be appended to the file.
func (k *KnownHostsFile) Open(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	err = k.Parse(f)
	if err != nil {
		_ = f.Close()
		return err
	}

	err = k.SetOutput(f)
	if err != nil {
		_ = f.Close()
		return err
	}

	return nil
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid entries are ignored.
func (k *KnownHostsFile) Parse(r io.Reader) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.hosts == nil {
		k.hosts = map[string]KnownHost{}
	}

	scanner := bufio.NewScanner(r)
	var line int
	for scanner.Scan() {
		line++

		text := scanner.Bytes()
		if len(text) == 0 {
			continue
		}

		var h KnownHost

		err := h.UnmarshalText(text)
		if err != nil {
			return fmt.Errorf("error when parsing line %d: %w",
				line, err)
		}

		k.hosts[h.Hostname] = h
	}

	err := scanner.Err()
	if err != nil {
		return fmt.Errorf("failed to read lines: %w", err)
	}

	return nil
}

func (k *KnownHostsFile) TOFU(hostname string, cert *x509.Certificate) error {
	host := NewKnownHost(hostname, cert.Raw, cert.NotAfter)

	knownHost, ok := k.Lookup(hostname)
	if !ok || time.Now().After(knownHost.Expires) {
		k.Add(host)
		return nil
	}

	// Check fingerprint
	if !bytes.Equal(knownHost.Fingerprint, host.Fingerprint) {
		return fmt.Errorf("fingerprint for %q does not match", hostname)
	}

	return nil
}

type Fingerprint []byte

func (f Fingerprint) String() string {
	var sb strings.Builder

	for i, b := range f {
		if i > 0 {
			sb.WriteByte(':')
		}

		fmt.Fprintf(&sb, "%02X", b)
	}

	return sb.String()
}

// KnownHost represents a known host entry for a fingerprint using a certain algorithm.
type KnownHost struct {
	Hostname    string      // hostname
	Algorithm   string      // fingerprint algorithm e.g. SHA-512
	Fingerprint Fingerprint // fingerprint
	Expires     time.Time   // unix time of the fingerprint expiration date
}

func (f *KnownHost) UnmarshalText(text []byte) error {
	const format = "hostname algorithm hex-fingerprint expiry-unix-ts"

	parts := bytes.Split(text, []byte(" "))
	if len(parts) != 4 {
		return fmt.Errorf(
			"expected the format %q", format)
	}

	if len(parts[0]) == 0 {
		return errors.New("empty hostname")
	}

	f.Hostname = string(parts[0])

	algorithm := string(parts[1])
	if algorithm != "SHA-512" {
		return fmt.Errorf(
			"unsupported algorithm %q", algorithm)
	}

	f.Algorithm = algorithm

	fingerprint := make([]byte, 0, sha512.Size)
	scan := bufio.NewScanner(bytes.NewReader(parts[2]))
	scan.Split(scanFingerprint)

	for scan.Scan() {
		b, err := strconv.ParseUint(scan.Text(), 16, 8)
		if err != nil {
			return fmt.Errorf("failed to parse fingerprint hash: %w", err)
		}
		fingerprint = append(fingerprint, byte(b))
	}

	if len(fingerprint) != sha512.Size {
		return fmt.Errorf("invalid fingerprint size %d, expected %d",
			len(fingerprint), sha512.Size)
	}

	f.Fingerprint = fingerprint

	unix, err := strconv.ParseInt(string(parts[3]), 10, 0)
	if err != nil {
		return fmt.Errorf(
			"invalid unix timestamp: %w", err)
	}

	f.Expires = time.Unix(unix, 0)

	return nil
}

func (h *KnownHost) WriteTo(w io.Writer) (int64, error) {
	bw := bufio.NewWriter(w)

	var written, n int

	n, _ = bw.WriteString(h.Hostname)
	bw.WriteByte(' ')
	written += n + 1

	n, _ = bw.WriteString(h.Algorithm)
	bw.WriteByte(' ')
	written += n + 1

	n, _ = bw.WriteString(h.Fingerprint.String())
	bw.WriteByte(' ')
	written += n + 1

	n, _ = bw.WriteString(strconv.FormatInt(h.Expires.Unix(), 10))
	written += n

	return int64(written), bw.Flush()
}

func scanFingerprint(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, ':'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, data[0:i], nil
	}

	// If we're at EOF, we have a final, non-terminated hex byte
	if atEOF {
		return len(data), data, nil
	}

	// Request more data.
	return 0, nil, nil
}

// NewKnownHost returns the known host entry with a SHA-512
// fingerprint of the provided raw data.
func NewKnownHost(hostname string, raw []byte, expires time.Time) KnownHost {
	sum := sha512.Sum512(raw)

	return KnownHost{
		Hostname:    hostname,
		Algorithm:   "SHA-512",
		Fingerprint: sum[:],
		Expires:     expires,
	}
}
