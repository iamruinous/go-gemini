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

This package provides an easy way to implement Trust-On-First-Use in your
clients. Here is a simple example client using TOFU to authenticate
certificates:

```go
client := &gemini.Client{
	KnownHosts: gemini.LoadKnownHosts(".local/share/gemini/known_hosts"),
	TrustCertificate: func(cert *x509.Certificate, knownHosts *gemini.KnownHosts) bool {
		// If the certificate is in the known hosts list, allow the connection
		if knownHosts.Has(cert) {
			return true
		}
		// Prompt the user
		if userTrustsCertificateTemporarily() {
			// Temporarily trust the certificate
			return true
		} else if userTrustsCertificatePermanently() {
			// Add the certificate to the known hosts file
			knownHosts.Add(cert)
			return true
		}
		// User does not trust the certificate
		return false
	},
}
```
