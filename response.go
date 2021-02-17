package gemini

import (
	"bufio"
	"crypto/tls"
	"io"
	"strconv"
)

// Response represents the response from a Gemini request.
//
// The Client returns Responses from servers once the response
// header has been received. The response body is streamed on demand
// as the Body field is read.
type Response struct {
	// Status contains the response status code.
	Status int

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the media type of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	// Body represents the response body.
	//
	// The response body is streamed on demand as the Body field
	// is read. If the network connection fails or the server
	// terminates the response, Body.Read calls return an error.
	//
	// The Gemini client guarantees that Body is always
	// non-nil, even on responses without a body or responses with
	// a zero-length body. It is the caller's responsibility to
	// close Body.
	Body io.ReadCloser

	// TLS contains information about the TLS connection on which the
	// response was received. It is nil for unencrypted responses.
	TLS *tls.ConnectionState
}

// ReadResponse reads a Gemini response from the provided io.ReadCloser.
func ReadResponse(rc io.ReadCloser) (*Response, error) {
	resp := &Response{}
	br := bufio.NewReader(rc)

	// Read the status
	statusB := make([]byte, 2)
	if _, err := br.Read(statusB); err != nil {
		return nil, err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	resp.Status = status

	// Read one space
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != ' ' {
		return nil, ErrInvalidResponse
	}

	// Read the meta
	meta, err := br.ReadString('\r')
	if err != nil {
		return nil, err
	}
	// Trim carriage return
	meta = meta[:len(meta)-1]
	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return nil, ErrInvalidResponse
	}
	// Default mime type of text/gemini; charset=utf-8
	if StatusClass(status) == StatusSuccess && meta == "" {
		meta = "text/gemini; charset=utf-8"
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrInvalidResponse
	}

	if StatusClass(status) == StatusSuccess {
		resp.Body = newReadCloserBody(br, rc)
	} else {
		resp.Body = nopReadCloser{}
		rc.Close()
	}
	return resp, nil
}

type nopReadCloser struct{}

func (nopReadCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (nopReadCloser) Close() error {
	return nil
}

type readCloserBody struct {
	br *bufio.Reader // used until empty
	io.ReadCloser
}

func newReadCloserBody(br *bufio.Reader, rc io.ReadCloser) io.ReadCloser {
	body := &readCloserBody{ReadCloser: rc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

func (b *readCloserBody) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadCloser.Read(p)
}

// A ResponseWriter interface is used by a Gemini handler
// to construct a Gemini response.
type ResponseWriter interface {
	// Header sets the response header.
	Header(status int, meta string)

	// Status sets the response status code.
	// It also sets the response meta to StatusText(status).
	Status(status int)

	// Meta sets the response meta.
	//
	// For successful responses, meta should contain the media type of the response.
	// For failure responses, meta should contain a short description of the failure.
	// The response meta should not be greater than 1024 bytes.
	Meta(meta string)

	// Write writes data to the connection as part of the response body.
	// If the response status does not allow for a response body, Write returns
	// ErrBodyNotAllowed.
	//
	// Write writes the response header if it has not already been written.
	// It writes a successful status code if one is not set.
	Write([]byte) (int, error)
}

// The Flusher interface is implemented by ResponseWriters that allow a
// Gemini handler to flush buffered data to the client.
//
// The default Gemini ResponseWriter implementation supports Flusher,
// but ResponseWriter wrappers may not. Handlers should always test
// for this ability at runtime.
type Flusher interface {
	// Flush sends any buffered data to the client.
	Flush() error
}

type responseWriter struct {
	b           *bufio.Writer
	status      int
	meta        string
	wroteHeader bool
	bodyAllowed bool
}

// NewResponseWriter returns a ResponseWriter that uses the provided io.Writer.
func NewResponseWriter(w io.Writer) ResponseWriter {
	return newResponseWriter(w)
}

func newResponseWriter(w io.Writer) *responseWriter {
	return &responseWriter{
		b: bufio.NewWriter(w),
	}
}

func (w *responseWriter) Header(status int, meta string) {
	w.status = status
	w.meta = meta
}

func (w *responseWriter) Status(status int) {
	w.status = status
	w.meta = StatusText(status)
}

func (w *responseWriter) Meta(meta string) {
	w.meta = meta
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.writeHeader(StatusSuccess)
	}
	if !w.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return w.b.Write(b)
}

func (w *responseWriter) writeHeader(defaultStatus int) {
	status := w.status
	if status == 0 {
		status = defaultStatus
	}

	meta := w.meta
	if StatusClass(status) == StatusSuccess {
		w.bodyAllowed = true

		if meta == "" {
			meta = "text/gemini"
		}
	}

	w.b.WriteString(strconv.Itoa(status))
	w.b.WriteByte(' ')
	w.b.WriteString(meta)
	w.b.Write(crlf)
	w.wroteHeader = true
}

func (w *responseWriter) Flush() error {
	if !w.wroteHeader {
		w.writeHeader(StatusTemporaryFailure)
	}
	// Write errors from writeHeader will be returned here.
	return w.b.Flush()
}
