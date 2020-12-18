// +build ignore

package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-xdg"
)

const trustPrompt = `The certificate offered by %s is of unknown trust. Its fingerprint is:
%s

If you knew the fingerprint to expect in advance, verify that this matches.
Otherwise, this should be safe to trust.

[t]rust always; trust [o]nce; [a]bort
=> `

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <url> [host]", os.Args[0])
		os.Exit(1)
	}

	// Load known hosts file
	var knownHosts gemini.KnownHostsFile
	if err := knownHosts.Load(filepath.Join(xdg.DataHome(), "gemini", "known_hosts")); err != nil {
		log.Println(err)
	}

	scanner := bufio.NewScanner(os.Stdin)

	var client gemini.Client
	client.TrustCertificate = func(hostname string, cert *x509.Certificate) error {
		knownHost, ok := knownHosts.Lookup(hostname)
		if ok && time.Now().Before(knownHost.Expires) {
			// Certificate is in known hosts file and is not expired
			return nil
		}

		fingerprint := gemini.NewFingerprint(cert.Raw, cert.NotAfter)
		fmt.Printf(trustPrompt, hostname, fingerprint.Hex)
		scanner.Scan()
		switch scanner.Text() {
		case "t":
			knownHosts.Add(hostname, fingerprint)
			knownHosts.Write(hostname, fingerprint)
			return nil
		case "o":
			knownHosts.Add(hostname, fingerprint)
			return nil
		default:
			return errors.New("certificate not trusted")
		}
	}
	client.GetInput = func(prompt string, sensitive bool) (string, bool) {
		fmt.Printf("%s ", prompt)
		scanner.Scan()
		return scanner.Text(), true
	}

	// Do the request
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

	// Handle response
	if resp.Status.Class() == gemini.StatusClassSuccess {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(body))
	} else {
		fmt.Printf("%d %s: %s\n", resp.Status, resp.Status.Message(), resp.Meta)
		os.Exit(1)
	}
}
