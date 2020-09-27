# go-gemini

[![GoDoc](https://godoc.org/git.sr.ht/~adnano/go-gemini?status.svg)](https://godoc.org/git.sr.ht/~adnano/go-gemini)

`go-gemini` implements the [Gemini protocol](https://gemini.circumlunar.space)
in Go.

It aims to provide an API similar to that of `net/http` to make it easy to
develop Gemini clients and servers.

## Examples

There are a few examples provided in the `examples` directory.
Some examples might require you to generate TLS certificates.

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
	to trust the certificate (see [Trust On First Use](#trust-on-first-use)).
2. Server recieves the request and constructs a response.
	The server calls the `Serve(*ResponseWriter, *Request)` method on the
	`Handler` field. The handler writes the response. The server then closes
	the connection.
3. Client recieves the response as a `*Response`. The client then handles the
	response.

## Trust On First Use

`go-gemini` makes it easy to implement Trust On First Use in your clients.

The default client loads known hosts from `$XDG_DATA_HOME/gemini/known_hosts`.
If that is all you need, you can simply use the top-level `Send` function:

```go
// Send uses the default client, which will load the default list of known hosts.
req := gemini.NewRequest("gemini://example.com")
gemini.Send(req)
```

Clients can also load their own list of known hosts:

```go
client := &Client{}
if err := client.KnownHosts.LoadFrom("path/to/my/known_hosts"); err != nil {
	log.Fatal(err)
}
```

Clients can then specify how to trust certificates in the `TrustCertificate`
field:

```go
client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
	// If the certificate is in the known hosts list, allow the connection
	return knownHosts.Lookup(hostname, cert)
}
```

Advanced clients can prompt the user for what to do when encountering an unknown
certificate. See `examples/client` for an example.

## Client Authentication

Gemini takes advantage of client certificates for authentication.

See `examples/auth` for an example server which authenticates its users with a
username and password, and uses their client certificate to remember sessions.
