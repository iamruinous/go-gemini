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
	"sort"
	"strconv"
	"strings"
	"sync"
)

// KnownHosts represents a list of known hosts.
// The zero value for KnownHosts represents an empty list ready to use.
//
// KnownHosts is safe for concurrent use by multiple goroutines.
type KnownHosts struct {
	hosts map[string]Host
	mu    sync.RWMutex
}

// Add adds a host to the list of known hosts.
func (k *KnownHosts) Add(h Host) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hosts == nil {
		k.hosts = map[string]Host{}
	}

	k.hosts[h.Hostname] = h
}

// Lookup returns the known host entry corresponding to the given hostname.
func (k *KnownHosts) Lookup(hostname string) (Host, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c, ok := k.hosts[hostname]
	return c, ok
}

// Entries returns the known host entries sorted by hostname.
func (k *KnownHosts) Entries() []Host {
	keys := make([]string, 0, len(k.hosts))
	for key := range k.hosts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	hosts := make([]Host, 0, len(k.hosts))
	for _, key := range keys {
		hosts = append(hosts, k.hosts[key])
	}
	return hosts
}

// WriteTo writes the list of known hosts to the provided io.Writer.
func (k *KnownHosts) WriteTo(w io.Writer) (int64, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var written int

	bw := bufio.NewWriter(w)
	for _, h := range k.hosts {
		n, err := bw.WriteString(h.String())
		written += n
		if err != nil {
			return int64(written), err
		}

		bw.WriteByte('\n')
		written += 1
	}

	return int64(written), bw.Flush()
}

// Load loads the known hosts entries from the provided path.
func (k *KnownHosts) Load(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return k.Parse(f)
}

// Parse parses the provided io.Reader and adds the parsed hosts to the list.
// Invalid entries are ignored.
//
// For more control over errors encountered during parsing, use bufio.Scanner
// in combination with ParseHost. For example:
//
//    var knownHosts tofu.KnownHosts
//    scanner := bufio.NewScanner(r)
//    for scanner.Scan() {
//        host, err := tofu.ParseHost(scanner.Bytes())
//        if err != nil {
//            // handle error
//        } else {
//            knownHosts.Add(host)
//        }
//    }
//    err := scanner.Err()
//    if err != nil {
//        // handle error
//    }
//
func (k *KnownHosts) Parse(r io.Reader) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.hosts == nil {
		k.hosts = map[string]Host{}
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Bytes()
		if len(text) == 0 {
			continue
		}

		h, err := ParseHost(text)
		if err != nil {
			continue
		}

		k.hosts[h.Hostname] = h
	}

	return scanner.Err()
}

// TOFU implements basic trust on first use.
//
// If the host is not on file, it is added to the list.
// If the fingerprint does not match the one on file, an error is returned.
func (k *KnownHosts) TOFU(hostname string, cert *x509.Certificate) error {
	host := NewHost(hostname, cert.Raw)
	knownHost, ok := k.Lookup(hostname)
	if !ok {
		k.Add(host)
		return nil
	}
	if !bytes.Equal(knownHost.Fingerprint, host.Fingerprint) {
		return fmt.Errorf("fingerprint for %q does not match", hostname)
	}
	return nil
}

// HostWriter writes host entries to an io.WriteCloser.
//
// HostWriter is safe for concurrent use by multiple goroutines.
type HostWriter struct {
	bw *bufio.Writer
	cl io.Closer
	mu sync.Mutex
}

// NewHostWriter returns a new host writer that writes to
// the provided io.WriteCloser.
func NewHostWriter(w io.WriteCloser) *HostWriter {
	return &HostWriter{
		bw: bufio.NewWriter(w),
		cl: w,
	}
}

// OpenHostsFile returns a new host writer that appends to the file at the given path.
// The file is created if it does not exist.
func OpenHostsFile(path string) (*HostWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return NewHostWriter(f), nil
}

// WriteHost writes the host to the underlying io.Writer.
func (h *HostWriter) WriteHost(host Host) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.bw.WriteString(host.String())
	h.bw.WriteByte('\n')

	if err := h.bw.Flush(); err != nil {
		return fmt.Errorf("failed to write host: %w", err)
	}
	return nil
}

// Close closes the underlying io.Closer.
func (h *HostWriter) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cl.Close()
}

// PersistentHosts represents a persistent set of known hosts.
type PersistentHosts struct {
	hosts  *KnownHosts
	writer *HostWriter
}

// NewPersistentHosts returns a new persistent set of known hosts that stores
// known hosts in hosts and writes new hosts to writer.
func NewPersistentHosts(hosts *KnownHosts, writer *HostWriter) *PersistentHosts {
	return &PersistentHosts{
		hosts,
		writer,
	}
}

// LoadPersistentHosts loads persistent hosts from the file at the given path.
func LoadPersistentHosts(path string) (*PersistentHosts, error) {
	hosts := &KnownHosts{}
	if err := hosts.Load(path); err != nil {
		return nil, err
	}
	writer, err := OpenHostsFile(path)
	if err != nil {
		return nil, err
	}
	return &PersistentHosts{
		hosts,
		writer,
	}, nil
}

// Add adds a host to the list of known hosts.
// It returns an error if the host could not be persisted.
func (p *PersistentHosts) Add(h Host) error {
	err := p.writer.WriteHost(h)
	if err != nil {
		return fmt.Errorf("failed to persist host: %w", err)
	}
	p.hosts.Add(h)
	return nil
}

// Lookup returns the known host entry corresponding to the given hostname.
func (p *PersistentHosts) Lookup(hostname string) (Host, bool) {
	return p.hosts.Lookup(hostname)
}

// Entries returns the known host entries sorted by hostname.
func (p *PersistentHosts) Entries() []Host {
	return p.hosts.Entries()
}

// TOFU implements trust on first use with a persistent set of known hosts.
//
// If the host is not on file, it is added to the list.
// If the fingerprint does not match the one on file, an error is returned.
func (p *PersistentHosts) TOFU(hostname string, cert *x509.Certificate) error {
	host := NewHost(hostname, cert.Raw)
	knownHost, ok := p.Lookup(hostname)
	if !ok {
		return p.Add(host)
	}
	if !bytes.Equal(knownHost.Fingerprint, host.Fingerprint) {
		return fmt.Errorf("fingerprint for %q does not match", hostname)
	}
	return nil
}

// Close closes the underlying HostWriter.
func (p *PersistentHosts) Close() error {
	return p.writer.Close()
}

// Host represents a host entry with a fingerprint using a certain algorithm.
type Host struct {
	Hostname    string      // hostname
	Algorithm   string      // fingerprint algorithm e.g. SHA-512
	Fingerprint Fingerprint // fingerprint
}

// NewHost returns a new host with a SHA-512 fingerprint of
// the provided raw data.
func NewHost(hostname string, raw []byte) Host {
	sum := sha512.Sum512(raw)

	return Host{
		Hostname:    hostname,
		Algorithm:   "SHA-512",
		Fingerprint: sum[:],
	}
}

// ParseHost parses a host from the provided text.
func ParseHost(text []byte) (Host, error) {
	var h Host
	err := h.UnmarshalText(text)
	return h, err
}

// String returns a string representation of the host.
func (h Host) String() string {
	var b strings.Builder
	b.WriteString(h.Hostname)
	b.WriteByte(' ')
	b.WriteString(h.Algorithm)
	b.WriteByte(' ')
	b.WriteString(h.Fingerprint.String())
	return b.String()
}

// UnmarshalText unmarshals the host from the provided text.
func (h *Host) UnmarshalText(text []byte) error {
	const format = "hostname algorithm hex-fingerprint expiry-unix-ts"

	parts := bytes.Split(text, []byte(" "))
	if len(parts) != 3 {
		return fmt.Errorf("expected the format %q", format)
	}

	if len(parts[0]) == 0 {
		return errors.New("empty hostname")
	}

	h.Hostname = string(parts[0])

	algorithm := string(parts[1])
	if algorithm != "SHA-512" {
		return fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	h.Algorithm = algorithm

	fingerprint := make([]byte, 0, sha512.Size)
	scanner := bufio.NewScanner(bytes.NewReader(parts[2]))
	scanner.Split(scanFingerprint)

	for scanner.Scan() {
		b, err := strconv.ParseUint(scanner.Text(), 16, 8)
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

	return nil
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

// Fingerprint represents a fingerprint.
type Fingerprint []byte

// String returns a string representation of the fingerprint.
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
