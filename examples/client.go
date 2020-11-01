// +build ignore

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"git.sr.ht/~adnano/go-gemini"
)

const trustPrompt = `The certificate offered by %s is of unknown trust. Its fingerprint is:
%s

If you knew the fingerprint to expect in advance, verify that this matches.
Otherwise, this should be safe to trust.

[t]rust always; trust [o]nce; [a]bort
=> `

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  = &gemini.Client{}
)

func init() {
	client.Timeout = 30 * time.Second
	client.KnownHosts.LoadDefault()
	client.TrustCertificate = func(hostname string, cert *x509.Certificate) gemini.Trust {
		fmt.Printf(trustPrompt, hostname, gemini.Fingerprint(cert))
		scanner.Scan()
		switch scanner.Text() {
		case "t":
			return gemini.TrustAlways
		case "o":
			return gemini.TrustOnce
		default:
			return gemini.TrustNone
		}
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

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.Status.Class() == gemini.StatusClassSuccess {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(body))
	} else {
		fmt.Printf("request failed: %d %s: %s", resp.Status, resp.Status.Message(), resp.Meta)
	}
}
