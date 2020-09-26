# go-gemini

[![GoDoc](https://godoc.org/git.sr.ht/~adnano/go-gemini?status.svg)](https://godoc.org/git.sr.ht/~adnano/go-gemini)

`go-gemini` implements the [Gemini protocol](https://gemini.circumlunar.space)
in Go.

It aims to provide an API similar to that of `net/http` to make it easy to
develop Gemini clients and servers.

## Examples

See `examples/client` and `examples/server` for an example client and server.

To run the examples:

	go run -tags=example ./examples/server

## Overview

A quick overview of the Gemini protocol:

1. Client opens connection
2. Server accepts connection
3. Client and server complete a TLS handshake
4. Client validates server certificate
5. Client sends request
6. Server sends response header
7. Server sends response body (only for successful responses)
8. Server closes connection
9. Client handles response

The way this is implemented in this package is like so:

1. Client makes a request with `NewRequest`. The client then sends the request
	with `(*Client).Send(*Request) (*Response, error)`. The client then determines whether
	to trust the certificate in `TrustCertificte(*x509.Certificate, *KnownHosts) bool`.
	(See [TOFU](#tofu)).
2. Server recieves the request and constructs a response.
	The server calls the `Serve(*ResponseWriter, *Request)` method on the
	`Handler` field. The handler writes the response. The server then closes
	the connection.
3. Client recieves the response as a `*Response`. The client then handles the
	response.

## TOFU

`go-gemini` makes it easy to implement Trust On First Use in your clients.

Clients can load the default list of known hosts:

```go
client := &Client{}
knownHosts, err := gemini.LoadKnownHosts()
if err != nil {
	log.Fatal(err)
}
client.KnownHosts = knownHosts
```

Clients can then specify how to trust certificates in the `TrustCertificate`
field:

```go
client.TrustCertificate = func(cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
	// If the certificate is in the known hosts list, allow the connection
	return knownHosts.Lookup(cert)
}
```

Advanced clients can prompt the user for what to do when encountering an unknown certificate:

```go
client := &gemini.Client{
	TrustCertificate: func(cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
		err := knownHosts.Lookup(cert)
		if err != nil {
			switch err {
			case gemini.ErrCertificateNotTrusted:
				// Alert the user that the certificate is not trusted
				alertUser()
			case gemini.ErrCertificateUnknown:
				// Prompt the user to trust the certificate
				if userTrustsCertificateTemporarily() {
					// Temporarily trust the certificate
					return nil
				} else if user.TrustsCertificatePermanently() {
					// Add the certificate to the known hosts file
					knownHosts.Add(cert)
					return nil
				}
			}
		}
		return err
	},
}
```
