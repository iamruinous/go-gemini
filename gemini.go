package gemini

import (
	"errors"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidRequest  = errors.New("gemini: invalid request")
	ErrInvalidResponse = errors.New("gemini: invalid response")

	ErrCertificateExpired = errors.New("gemini: certificate expired")

	// ErrBodyNotAllowed is returned by ResponseWriter.Write calls
	// when the response status code does not permit a body.
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow body")

	// ErrHijacked is returned by ResponseWriter.Write calls when
	// the underlying connection has been hijacked using the
	// Hijacker interface. A zero-byte write on a hijacked
	// connection will return ErrHijacked without any other side
	// effects.
	ErrHijacked = errors.New("gemini: connection has been hijacked")
)
