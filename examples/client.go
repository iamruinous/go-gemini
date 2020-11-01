// +build ignore

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  = &gemini.Client{}
)

func init() {
	client.Timeout = 2 * time.Minute
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
	client.CreateCertificate = func(hostname, path string) (tls.Certificate, error) {
		fmt.Println("Generating client certificate for", hostname, path)
		return gemini.CreateCertificate(gemini.CertificateOptions{
			Duration: time.Hour,
		})
	}
	client.GetInput = func(prompt string, sensitive bool) (string, bool) {
		fmt.Printf("%s: ", prompt)
		scanner.Scan()
		return scanner.Text(), true
	}
}

func doRequest(req *gemini.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.Status.Class() == gemini.StatusClassSuccess {
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		fmt.Print(string(body))
		return nil
	}
	return fmt.Errorf("request failed: %d %s: %s", resp.Status, resp.Status.Message(), resp.Meta)
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
		fmt.Printf("usage: %s gemini://... [host]", os.Args[0])
		os.Exit(1)
	}

	url := os.Args[1]
	req, err := gemini.NewRequest(url)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(os.Args) == 3 {
		req.Host = os.Args[2]
	}

	if err := doRequest(req); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
