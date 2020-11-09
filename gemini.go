/*
Package gemini implements the Gemini protocol.

Client is a Gemini client.

	client := &gemini.Client{}
	resp, err := client.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	if resp.Status.Class() == gemini.StatusClassSucess {
		defer resp.Body.Close()
		// ...
	}
	// ...

Server is a Gemini server.

	server := &gemini.Server{
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
	}

Servers should be configured with certificates:

	err := server.Certificates.Load("/var/lib/gemini/certs")
	if err != nil {
		// handle error
	}

Servers can accept requests for multiple hosts and schemes:

	server.RegisterFunc("example.com", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Welcome to example.com")
	})
	server.RegisterFunc("example.org", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Welcome to example.org")
	})
	server.RegisterFunc("http://example.net", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Proxied content from http://example.net")
	})

To start the server, call ListenAndServe:

	err := server.ListenAndServe()
	if err != nil {
		// handle error
	}
*/
package gemini

import (
	"errors"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidURL      = errors.New("gemini: invalid URL")
	ErrInvalidResponse = errors.New("gemini: invalid response")
	ErrBodyNotAllowed  = errors.New("gemini: response body not allowed")
)
