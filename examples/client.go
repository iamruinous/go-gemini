// +build ignore

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  = &gemini.Client{}
)

func init() {
	client.KnownHosts.LoadDefault()
	client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
		err := knownHosts.Lookup(hostname, cert)
		if err != nil {
			switch err {
			case gemini.ErrCertificateNotTrusted:
				// Alert the user that the certificate is not trusted
				fmt.Printf("Warning: Certificate for %s is not trusted!\n", hostname)
				fmt.Println("This could indicate a Man-in-the-Middle attack.")
			case gemini.ErrCertificateUnknown:
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
	client.GetCertificate = func(hostname string, store *gemini.CertificateStore) *tls.Certificate {
		// If the certificate is in the store, return it
		if cert, err := store.Lookup(hostname); err == nil {
			return cert
		}
		// Otherwise, generate a certificate
		fmt.Println("Generating client certificate for", hostname)
		duration := time.Hour
		cert, err := gemini.NewCertificate(hostname, duration)
		if err != nil {
			return nil
		}
		// Store and return the certificate
		store.Add(hostname, cert)
		return &cert
	}
}

// sendRequest sends a request to the given URL.
func sendRequest(req *gemini.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	switch resp.Status.Class() {
	case gemini.StatusClassInput:
		fmt.Printf("%s: ", resp.Meta)
		scanner.Scan()
		req.URL.RawQuery = url.QueryEscape(scanner.Text())
		return sendRequest(req)
	case gemini.StatusClassSuccess:
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		fmt.Print(string(body))
		return nil
	case gemini.StatusClassRedirect:
		// This should not happen unless CheckRedirect returns false.
		return fmt.Errorf("Failed to redirect to %s", resp.Meta)
	case gemini.StatusClassTemporaryFailure:
		return fmt.Errorf("Temporary failure: %s", resp.Meta)
	case gemini.StatusClassPermanentFailure:
		return fmt.Errorf("Permanent failure: %s", resp.Meta)
	case gemini.StatusClassCertificateRequired:
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
	fmt.Printf(trustPrompt, gemini.Fingerprint(cert))
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

	url := os.Args[1]
	req, err := gemini.NewRequest(url)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := sendRequest(req); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
