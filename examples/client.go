// +build ignore

package main

import (
	"bufio"
	"crypto/x509"
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

var (
	scanner = bufio.NewScanner(os.Stdin)
	client  = &gemini.Client{}
)

func init() {
	client.Timeout = 30 * time.Second
	client.KnownHosts.Load(filepath.Join(xdg.DataHome(), "gemini", "known_hosts"))
	client.TrustCertificate = func(hostname string, cert *x509.Certificate) gemini.Trust {
		fingerprint := gemini.NewFingerprint(cert.Raw, cert.NotAfter)
		fmt.Printf(trustPrompt, hostname, fingerprint.Hex)
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

	if resp.Status.Class() == gemini.StatusClassSuccess {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(string(body))
	} else {
		fmt.Printf("request failed: %d %s: %s", resp.Status, resp.Status.Message(), resp.Meta)
	}
}
