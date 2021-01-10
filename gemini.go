package gemini

import (
	"errors"
)

var crlf = []byte("\r\n")

// Errors.
var (
	ErrInvalidURL      = errors.New("gemini: invalid URL")
	ErrInvalidRequest  = errors.New("gemini: invalid request")
	ErrInvalidResponse = errors.New("gemini: invalid response")
	ErrBodyNotAllowed  = errors.New("gemini: response body not allowed")
)
