// +build example

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"git.sr.ht/~adnano/go-gemini"
)

var (
	client *gemini.Client
	cert   tls.Certificate
)

func init() {
	// Load the list of known hosts
	knownHosts, err := gemini.LoadKnownHosts()
	if err != nil {
		log.Fatal(err)
	}

	client = &gemini.Client{
		KnownHosts: knownHosts,
	}

	client.TrustCertificate = func(cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
		err := knownHosts.Lookup(cert)
		if err != nil {
			switch err {
			case gemini.ErrCertificateNotTrusted:
				// Alert the user that the certificate is not trusted
				fmt.Println("error: certificate is not trusted!")
				fmt.Println("This could indicate a Man-in-the-Middle attack.")
			case gemini.ErrCertificateUnknown:
				// Prompt the user to trust the certificate
				if userTrustsCertificateTemporarily() {
					// Temporarily trust the certificate
					return nil
				} else if userTrustsCertificatePermanently() {
					// Add the certificate to the known hosts file
					knownHosts.Add(cert)
					return nil
				}
			}
		}
		return err
	}

	// Configure a client side certificate.
	// To generate a certificate, run:
	//
	//     openssl genrsa -out client.key 2048
	//     openssl ecparam -genkey -name secp384r1 -out client.key
	//     openssl req -new -x509 -sha512 -key client.key -out client.crt -days 365
	//
	cert, err = tls.LoadX509KeyPair("examples/client/client.crt", "examples/client/client.key")
	if err != nil {
		log.Fatal(err)
	}
}

func makeRequest(url string) {
	req, err := gemini.NewRequest(url)
	if err != nil {
		log.Fatal(err)
	}
	req.Certificate = cert

	resp, err := client.Send(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Status code:", resp.Status)
	fmt.Println("Meta:", resp.Meta)

	switch resp.Status / 10 {
	case gemini.StatusClassInput:
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("%s: ", resp.Meta)
		scanner.Scan()
		query := scanner.Text()
		makeRequest(url + "?" + query)
		return
	case gemini.StatusClassSuccess:
		fmt.Print("Body:\n", string(resp.Body))
	case gemini.StatusClassRedirect:
		log.Print("Redirecting to ", resp.Meta)
		makeRequest(resp.Meta)
		return
	case gemini.StatusClassTemporaryFailure:
		log.Fatal("Temporary failure")
	case gemini.StatusClassPermanentFailure:
		log.Fatal("Permanent failure")
	case gemini.StatusClassClientCertificateRequired:
		log.Fatal("Client certificate required")
	default:
		log.Fatal("Protocol error")
	}
}

func userTrustsCertificateTemporarily() bool {
	fmt.Print("Do you want to trust the certificate temporarily? (y/n) ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text() == "y"
}

func userTrustsCertificatePermanently() bool {
	fmt.Print("How about permanently? (y/n) ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text() == "y"
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s gemini://...", os.Args[0])
	}
	makeRequest(os.Args[1])
}
