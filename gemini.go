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

// Errors.
var (
	ErrInvalidRequest  = errors.New("gemini: invalid request")
	ErrInvalidResponse = errors.New("gemini: invalid response")

	// ErrBodyNotAllowed is returned by ResponseWriter.Write calls
	// when the response status code does not permit a body.
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow body")
)

var crlf = []byte("\r\n")

func trimCRLF(b []byte) ([]byte, bool) {
	// Check for CR
	if len(b) < 2 || b[len(b)-2] != '\r' {
		return nil, false
	}
	// Trim CRLF
	b = b[:len(b)-2]
	return b, true
}
