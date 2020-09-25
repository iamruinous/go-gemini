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
	client = &gemini.Client{
		VerifyCertificate: func(cert *x509.Certificate) error {
			// if gemini.Fingerprint(cert) != expected {
			// 	return errors.New("invalid server certificate")
			// }
			return nil
		},
	}

	cert tls.Certificate
)

func init() {
	// Configure a client side certificate.
	// To generate a certificate, run:
	//
	//     openssl genrsa -out client.key 2048
	//     openssl ecparam -genkey -name secp384r1 -out client.key
	//     openssl req -new -x509 -sha256 -key client.key -out client.crt -days 3650
	//
	var err error
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

	fmt.Println(gemini.Fingerprint(resp.TLS.PeerCertificates[0]))

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

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s gemini://...", os.Args[0])
	}
	makeRequest(os.Args[1])
}
