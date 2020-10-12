// +build example

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"git.sr.ht/~adnano/gmi"
)

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  = &gmi.Client{}
)

func init() {
	// Initialize the client
	client.KnownHosts.Load() // Load known hosts
	client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gmi.KnownHosts) error {
		err := knownHosts.Lookup(hostname, cert)
		if err != nil {
			switch err {
			case gmi.ErrCertificateNotTrusted:
				// Alert the user that the certificate is not trusted
				fmt.Printf("Warning: Certificate for %s is not trusted!\n", hostname)
				fmt.Println("This could indicate a Man-in-the-Middle attack.")
			case gmi.ErrUnknownCertificate:
				// Prompt the user to trust the certificate
				trust := trustCertificate(cert)
				switch trust {
				case trustOnce:
					// Temporarily trust the certificate
					knownHosts.AddTemporary(hostname, cert)
					return nil
				case trustAlways:
					// Add the certificate to the known hosts file
					knownHosts.Add(hostname, cert)
					return nil
				}
			}
		}
		return err
	}
	client.GetCertificate = func(hostname string, store gmi.CertificateStore) *tls.Certificate {
		// If the certificate is in the store, return it
		if cert, ok := store[hostname]; ok {
			return cert
		}
		// Otherwise, generate a certificate
		fmt.Println("Generating client certificate for", hostname)
		duration := time.Hour
		cert, err := gmi.NewCertificate(hostname, duration)
		if err != nil {
			return nil
		}
		// Store and return the certificate
		store[hostname] = &cert
		return &cert
	}
}

// sendRequest sends a request to the given URL.
func sendRequest(req *gmi.Request) error {
	resp, err := client.Send(req)
	if err != nil {
		return err
	}

	// TODO: More fine-grained analysis of the status code.
	switch resp.Status / 10 {
	case gmi.StatusClassInput:
		fmt.Printf("%s: ", resp.Meta)
		scanner.Scan()
		req.URL.RawQuery = scanner.Text()
		return sendRequest(req)
	case gmi.StatusClassSuccess:
		fmt.Print(string(resp.Body))
		return nil
	case gmi.StatusClassRedirect:
		fmt.Println("Redirecting to", resp.Meta)
		// Make the request to the same host
		red, err := gmi.NewRequestTo(resp.Meta, req.Host)
		if err != nil {
			return err
		}
		// Handle relative redirects
		red.URL = req.URL.ResolveReference(red.URL)
		return sendRequest(red)
	case gmi.StatusClassTemporaryFailure:
		return fmt.Errorf("Temporary failure: %s", resp.Meta)
	case gmi.StatusClassPermanentFailure:
		return fmt.Errorf("Permanent failure: %s", resp.Meta)
	case gmi.StatusClassCertificateRequired:
		// Note that this should not happen unless the server responds with
		// CertificateRequired even after we send a certificate.
		// CertificateNotAuthorized and CertificateNotValid are handled here.
		return fmt.Errorf("Certificate required: %s", resp.Meta)
	}
	panic("unreachable")
}

type trust int

const (
	trustAbort trust = iota
	trustOnce
	trustAlways
)

const trustPrompt = `The certificate offered by this server is of unknown trust. Its fingerprint is:
%s

If you knew the fingerprint to expect in advance, verify that this matches.
Otherwise, this should be safe to trust.

[t]rust always; trust [o]nce; [a]bort
=> `

func trustCertificate(cert *x509.Certificate) trust {
	fmt.Printf(trustPrompt, gmi.Fingerprint(cert))
	scanner.Scan()
	switch scanner.Text() {
	case "t":
		return trustAlways
	case "o":
		return trustOnce
	default:
		return trustAbort
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s gemini://...", os.Args[0])
		os.Exit(1)
	}

	var host string
	if len(os.Args) >= 3 {
		host = os.Args[2]
	}

	url := os.Args[1]
	var req *gmi.Request
	var err error
	if host != "" {
		req, err = gmi.NewRequestTo(url, host)
	} else {
		req, err = gmi.NewRequest(url)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := sendRequest(req); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
