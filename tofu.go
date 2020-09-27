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
// The zero value for KnownHosts is an empty list ready to use.
type KnownHosts struct {
	hosts []KnownHost
	file  *os.File
}

// Load loads the known hosts from the default known hosts path, which is
// `$XDG_DATA_HOME/gemini/known_hosts`.
// It creates the path and any of its parent directories if they do not exist.
// KnownHosts will append to the file whenever a certificate is added.
func (k *KnownHosts) Load() error {
	path, err := defaultKnownHostsPath()
	if err != nil {
		return err
	}
	return k.LoadFrom(path)
}

// LoadFrom loads the known hosts from the provided path.
// It creates the path and any of its parent directories if they do not exist.
// KnownHosts will append to the file whenever a certificate is added.
func (k *KnownHosts) LoadFrom(path string) error {
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
func (k *KnownHosts) Add(cert *x509.Certificate) {
	// Add an entry per hostname
	for _, name := range cert.DNSNames {
		host := NewKnownHost(name, cert)
		k.hosts = append(k.hosts, host)
		// Append to the file
		if k.file != nil {
			host.Write(k.file)
		}
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

// Write writes the known hosts to the provided io.Writer.
func (k *KnownHosts) Write(w io.Writer) {
	for _, h := range k.hosts {
		h.Write(w)
	}
}

// KnownHost represents a known host.
type KnownHost struct {
	Hostname    string // e.g. gemini.circumlunar.space
	Algorithm   string // fingerprint algorithm e.g. SHA-512
	Fingerprint string // fingerprint in hexadecimal, with ':' between each octet
	Expires     int64  // unix time of certificate notAfter date
}

// NewKnownHost creates a new known host from a hostname and a certificate.
func NewKnownHost(hostname string, cert *x509.Certificate) KnownHost {
	return KnownHost{
		Hostname:    hostname,
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
