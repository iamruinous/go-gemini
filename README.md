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

1. Client makes a request with `NewRequest`. The client can verify server
   certificates in the Request options, see [Recommended TLS
   configuration](#recommended-tls-configuration).
2. Server recieves the request and constructs a response.
	The server calls the `Serve(*ResponseWriter, *Request)` method on the
	`Handler` field. The handler writes the response. The server then closes
	the connection.
5. Client recieves the response as a `*Response`. The client then handles the
   response. The client can now verify the certificate of the server using a
   Trust-On-First-Use method.

## Recommended TLS configuration

For clients, the recommended TLS configuration is as follows:

```go
// Accept self-signed server certificates
req.TLSConfig.InsecureSkipVerify = true
// Manually verify server certificates, using TOFU
req.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
	// Verify the server certificate here
	// Return an error on failure, or nil on success
	return nil
}
```

Note that `gemini.Get` does not verify server certificates.

For servers, the recommended TLS configuration is as follows:

```go
// Specify a certificate
// To load a certificate, use `tls.LoadX509KeyPair`.
srv.TLSConfig.Certificates = append(srv.TLSConfig.Certificates, cert)
// Request client certificates
srv.TLSConfig.ClientAuth = tls.RequestClientCert
```
