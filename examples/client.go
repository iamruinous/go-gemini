// +build ignore

// This example illustrates a Gemini client.

package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-xdg"
)

var (
	hosts   gemini.KnownHostsFile
	scanner *bufio.Scanner
)

func init() {
	// Load known hosts file
	path := filepath.Join(xdg.DataHome(), "gemini", "known_hosts")
	err := hosts.Load(path)
	if err != nil {
		log.Println(err)
	}

	scanner = bufio.NewScanner(os.Stdin)
}

const trustPrompt = `The certificate offered by %s is of unknown trust. Its fingerprint is:
%s

If you knew the fingerprint to expect in advance, verify that this matches.
Otherwise, this should be safe to trust.

[t]rust always; trust [o]nce; [a]bort
=> `

func trustCertificate(hostname string, cert *x509.Certificate) error {
	knownHost, ok := hosts.Lookup(hostname)
	if ok && time.Now().Before(knownHost.Expires) {
		// Certificate is in known hosts file and is not expired
		return nil
	}

	fingerprint := gemini.NewFingerprint(cert.Raw, cert.NotAfter)
	fmt.Printf(trustPrompt, hostname, fingerprint.Hex)
	scanner.Scan()
	switch scanner.Text() {
	case "t":
		hosts.Add(hostname, fingerprint)
		hosts.Write(hostname, fingerprint)
		return nil
	case "o":
		hosts.Add(hostname, fingerprint)
		return nil
	default:
		return errors.New("certificate not trusted")
	}
}

func getInput(prompt string, sensitive bool) (input string, ok bool) {
	fmt.Printf("%s ", prompt)
	scanner.Scan()
	return scanner.Text(), true
}

func do(req *gemini.Request, via []*gemini.Request) (*gemini.Response, error) {
	client := gemini.Client{
		TrustCertificate: trustCertificate,
	}
	resp, err := client.Do(req)
	if err != nil {
		return resp, err
	}

	switch resp.Status.Class() {
	case gemini.StatusClassInput:
		input, ok := getInput(resp.Meta, resp.Status == gemini.StatusSensitiveInput)
		if !ok {
			break
		}
		req.URL.ForceQuery = true
		req.URL.RawQuery = gemini.QueryEscape(input)
		return do(req, via)

	case gemini.StatusClassRedirect:
		via = append(via, req)
		if len(via) > 5 {
			return resp, errors.New("too many redirects")
		}

		target, err := url.Parse(resp.Meta)
		if err != nil {
			return resp, err
		}
		target = req.URL.ResolveReference(target)
		redirect := *req
		redirect.URL = target
		return do(&redirect, via)
	}

	return resp, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <url> [host]\n", os.Args[0])
		os.Exit(1)
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
	resp, err := do(req, nil)
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
