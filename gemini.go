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

	// ErrHandlerTimeout is returned on ResponseWriter Write calls
	// in handlers which have timed out.
	ErrHandlerTimeout = errors.New("gemini: Handler timeout")
)
