// +build example

package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"

	"git.sr.ht/~adnano/go-gemini"
)

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  *gemini.Client
)

func init() {
	// Initialize the client
	client = &gemini.Client{}
	client.KnownHosts.Load() // Load known hosts
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
}

// sendRequest sends a request to the given url.
func sendRequest(req *gemini.Request) error {
	resp, err := client.Send(req)
	if err != nil {
		return err
	}

	switch resp.Status / 10 {
	case gemini.StatusClassInput:
		fmt.Printf("%s: ", resp.Meta)
		scanner.Scan()
		req.URL.RawQuery = scanner.Text()
		return sendRequest(req)
	case gemini.StatusClassSuccess:
		fmt.Print(string(resp.Body))
		return nil
	case gemini.StatusClassRedirect:
		fmt.Println("Redirecting to ", resp.Meta)
		req, err := gemini.NewRequest(resp.Meta)
		if err != nil {
			return err
		}
		return sendRequest(req)
	case gemini.StatusClassTemporaryFailure:
		return fmt.Errorf("Temporary failure: %s", resp.Meta)
	case gemini.StatusClassPermanentFailure:
		return fmt.Errorf("Permanent failure: %s", resp.Meta)
	case gemini.StatusClassClientCertificateRequired:
		fmt.Println("Generating client certificate for", req.Hostname())
		return nil // TODO: Generate and store client certificate
	default:
		return fmt.Errorf("Protocol error: Server sent an invalid response")
	}
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
		fmt.Println("usage: %s gemini://...", os.Args[0])
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
