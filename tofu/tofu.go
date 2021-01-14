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

// HostsFile represents a list of known hosts optionally loaded from a file.
// The zero value for HostsFile represents an empty list ready to use.
//
// HostsFile is safe for concurrent use by multiple goroutines.
type HostsFile struct {
	hosts  map[string]Host
	writer *bufio.Writer
	closer io.Closer
	mu     sync.RWMutex
}

// SetOutput sets the output to which new known hosts will be written to.
func (k *HostsFile) SetOutput(w io.WriteCloser) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.writer != nil {
		err := k.closer.Close()
		if err != nil {
			return fmt.Errorf("failed to close previous output: %w", err)
		}
	}

	k.writer = bufio.NewWriter(w)
	k.closer = w

	return nil
}

// Close closes the output.
func (k *HostsFile) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.writer == nil {
		return nil
	}

	err := k.closer.Close()
	if err != nil {
		return err
	}

	k.writer = nil
	k.closer = nil

	return nil
}

// Add adds a known host to the list of known hosts.
func (k *HostsFile) Add(h Host) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hosts == nil {
		k.hosts = map[string]Host{}
	}

	k.hosts[h.Hostname] = h

	if k.writer != nil {
		h.WriteTo(k.writer)
		k.writer.WriteByte('\n')

		if err := k.writer.Flush(); err != nil {
			return fmt.Errorf("failed to write to known host file: %w", err)
		}
	}

	return nil
}

// Lookup returns the fingerprint of the certificate corresponding to
// the given hostname.
func (k *HostsFile) Lookup(hostname string) (Host, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c, ok := k.hosts[hostname]
	return c, ok
}

// WriteAll writes all of the known hosts to the provided io.Writer.
func (k *HostsFile) WriteTo(w io.Writer) (int64, error) {
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
func (k *HostsFile) Open(path string) error {
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
func (k *HostsFile) Parse(r io.Reader) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.hosts == nil {
		k.hosts = map[string]Host{}
	}

	scanner := bufio.NewScanner(r)
	var line int
	for scanner.Scan() {
		line++

		text := scanner.Bytes()
		if len(text) == 0 {
			continue
		}

		var h Host

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

func (k *HostsFile) TOFU(hostname string, cert *x509.Certificate) error {
	host := NewHost(hostname, cert.Raw, cert.NotAfter)

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

// Host represents a known host entry for a fingerprint using a certain algorithm.
type Host struct {
	Hostname    string      // hostname
	Algorithm   string      // fingerprint algorithm e.g. SHA-512
	Fingerprint Fingerprint // fingerprint
	Expires     time.Time   // unix time of the fingerprint expiration date
}

// NewHost returns the known host entry with a SHA-512
// fingerprint of the provided raw data.
func NewHost(hostname string, raw []byte, expires time.Time) Host {
	sum := sha512.Sum512(raw)

	return Host{
		Hostname:    hostname,
		Algorithm:   "SHA-512",
		Fingerprint: sum[:],
		Expires:     expires,
	}
}

func (h *Host) UnmarshalText(text []byte) error {
	const format = "hostname algorithm hex-fingerprint expiry-unix-ts"

	parts := bytes.Split(text, []byte(" "))
	if len(parts) != 4 {
		return fmt.Errorf(
			"expected the format %q", format)
	}

	if len(parts[0]) == 0 {
		return errors.New("empty hostname")
	}

	h.Hostname = string(parts[0])

	algorithm := string(parts[1])
	if algorithm != "SHA-512" {
		return fmt.Errorf(
			"unsupported algorithm %q", algorithm)
	}

	h.Algorithm = algorithm

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

	h.Fingerprint = fingerprint

	unix, err := strconv.ParseInt(string(parts[3]), 10, 0)
	if err != nil {
		return fmt.Errorf(
			"invalid unix timestamp: %w", err)
	}

	h.Expires = time.Unix(unix, 0)

	return nil
}

func (h *Host) WriteTo(w io.Writer) (int64, error) {
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
