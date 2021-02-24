package gemini

import (
	"errors"
	"mime"
)

func init() {
	// Add Gemini mime types
	mime.AddExtensionType(".gmi", "text/gemini")
	mime.AddExtensionType(".gemini", "text/gemini")
}

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidRequest  = errors.New("gemini: invalid request")
	ErrInvalidResponse = errors.New("gemini: invalid response")

	ErrCertificateExpired = errors.New("gemini: certificate expired")

	// ErrBodyNotAllowed is returned by ResponseWriter.Write calls
	// when the response status code does not permit a body.
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow body")
)
