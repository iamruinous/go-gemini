package gmi

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
// The zero value for KnownHosts is an empty list ready to use.
type KnownHosts struct {
	hosts map[string]certInfo
	file  *os.File
}

// LoadDefault loads the known hosts from the default known hosts path, which is
// $XDG_DATA_HOME/gemini/known_hosts.
// It creates the path and any of its parent directories if they do not exist.
// KnownHosts will append to the file whenever a certificate is added.
func (k *KnownHosts) LoadDefault() error {
	path, err := defaultKnownHostsPath()
	if err != nil {
		return err
	}
	return k.Load(path)
}

// Load loads the known hosts from the provided path.
// It creates the path and any of its parent directories if they do not exist.
// KnownHosts will append to the file whenever a certificate is added.
func (k *KnownHosts) Load(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}
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

// AddTemporary adds a certificate to the list of known hosts
// without writing it to the known hosts file.
func (k *KnownHosts) AddTemporary(hostname string, cert *x509.Certificate) {
	k.add(hostname, cert, false)
}

func (k *KnownHosts) add(hostname string, cert *x509.Certificate, write bool) {
	if k.hosts == nil {
		k.hosts = map[string]certInfo{}
	}
	info := certInfo{
		Algorithm:   "SHA-512",
		Fingerprint: Fingerprint(cert),
		Expires:     cert.NotAfter.Unix(),
	}
	k.hosts[hostname] = info
	// Append to the file
	if write && k.file != nil {
		appendKnownHost(k.file, hostname, info)
	}
}

// Lookup looks for the provided certificate in the list of known hosts.
// If the hostname is in the list, but the fingerprint differs,
// Lookup returns ErrCertificateNotTrusted.
// If the hostname is not in the list, Lookup returns ErrCertificateUnknown.
// If the certificate is found and the fingerprint matches, error will be nil.
func (k *KnownHosts) Lookup(hostname string, cert *x509.Certificate) error {
	now := time.Now().Unix()
	fingerprint := Fingerprint(cert)
	if c, ok := k.hosts[hostname]; ok {
		if c.Expires <= now {
			// Certificate is expired
			return ErrCertificateUnknown
		}
		if c.Fingerprint != fingerprint {
			// Fingerprint does not match
			return ErrCertificateNotTrusted
		}
		// Certificate is trusted
		return nil
	}
	return ErrCertificateUnknown
}

// Parse parses the provided reader and adds the parsed known hosts to the list.
// Invalid lines are ignored.
func (k *KnownHosts) Parse(r io.Reader) {
	if k.hosts == nil {
		k.hosts = map[string]certInfo{}
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

		k.hosts[hostname] = certInfo{
			Algorithm:   algorithm,
			Fingerprint: fingerprint,
			Expires:     expires,
		}
	}
}

// Write writes the known hosts to the provided io.Writer.
func (k *KnownHosts) Write(w io.Writer) {
	for h, c := range k.hosts {
		appendKnownHost(w, h, c)
	}
}

type certInfo struct {
	Algorithm   string // fingerprint algorithm e.g. SHA-512
	Fingerprint string // fingerprint in hexadecimal, with ':' between each octet
	Expires     int64  // unix time of certificate notAfter date
}

func appendKnownHost(w io.Writer, hostname string, c certInfo) (int, error) {
	return fmt.Fprintf(w, "%s %s %s %d\n", hostname, c.Algorithm, c.Fingerprint, c.Expires)
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

// defaultKnownHostsPath returns the default known_hosts path.
// The default path is $XDG_DATA_HOME/gemini/known_hosts
func defaultKnownHostsPath() (string, error) {
	dataDir, err := userDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "gemini", "known_hosts"), nil
}

// userDataDir returns the user data directory.
func userDataDir() (string, error) {
	dataDir, ok := os.LookupEnv("XDG_DATA_HOME")
	if ok {
		return dataDir, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}
