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

	// ErrBodyNotAllowed is returned by ResponseWriter.Write calls
	// when the response status code does not permit a body.
	ErrBodyNotAllowed = errors.New("gemini: response status code does not allow body")

	// ErrServerClosed is returned by the Server's Serve and ListenAndServe
	// methods after a call to Shutdown or Close.
	ErrServerClosed = errors.New("gemini: server closed")

	// ErrAbortHandler is a sentinel panic value to abort a handler.
	// While any panic from ServeGemini aborts the response to the client,
	// panicking with ErrAbortHandler also suppresses logging of a stack
	// trace to the server's error log.
	ErrAbortHandler = errors.New("gemini: abort Handler")

	// ErrHandlerTimeout is returned on ResponseWriter Write calls
	// in handlers which have timed out.
	ErrHandlerTimeout = errors.New("gemini: Handler timeout")
)
