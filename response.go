package gemini

import (
	"bufio"
	"crypto/tls"
	"io"
	"strconv"
)

// Response is a Gemini response.
type Response struct {
	// Status contains the response status code.
	Status Status

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the media type of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	// Body contains the response body for successful responses.
	Body io.ReadCloser

	// TLS contains information about the TLS connection on which the response
	// was received.
	TLS tls.ConnectionState
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
		return nil, err
	}
	resp.Status = Status(status)

	// Disregard invalid status codes
	const minStatus, maxStatus = 1, 6
	statusClass := resp.Status.Class()
	if statusClass < minStatus || statusClass > maxStatus {
		return nil, ErrInvalidResponse
	}

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
	if statusClass == StatusClassSuccess && meta == "" {
		meta = "text/gemini; charset=utf-8"
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrInvalidResponse
	}

	if resp.Status.Class() == StatusClassSuccess {
		resp.Body = newReadCloserBody(br, rc)
	} else {
		rc.Close()
	}
	return resp, nil
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

// ResponseWriter is used to construct a Gemini response.
type ResponseWriter struct {
	b           *bufio.Writer
	status      Status
	meta        string
	setHeader   bool
	wroteHeader bool
	bodyAllowed bool
}

// NewResponseWriter returns a ResponseWriter that uses the provided io.Writer.
func NewResponseWriter(w io.Writer) *ResponseWriter {
	return &ResponseWriter{
		b: bufio.NewWriter(w),
	}
}

// Header sets the response header.
func (w *ResponseWriter) Header(status Status, meta string) {
	w.status = status
	w.meta = meta
}

// Status sets the response status code.
// It also sets the response meta to status.Meta().
func (w *ResponseWriter) Status(status Status) {
	w.status = status
	w.meta = status.Meta()
}

// Meta sets the response meta.
//
// For successful responses, meta should contain the media type of the response.
// For failure responses, meta should contain a short description of the failure.
// The response meta should not be greater than 1024 bytes.
func (w *ResponseWriter) Meta(meta string) {
	w.meta = meta
}

// Write writes data to the connection as part of the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
//
// Write writes the response header if it has not already been written.
// It writes a successful status code if one is not set.
func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.writeHeader(StatusSuccess)
	}
	if !w.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return w.b.Write(b)
}

func (w *ResponseWriter) writeHeader(defaultStatus Status) {
	status := w.status
	if status == 0 {
		status = defaultStatus
	}

	meta := w.meta
	if status.Class() == StatusClassSuccess {
		w.bodyAllowed = true

		if meta == "" {
			meta = "text/gemini"
		}
	}

	w.b.WriteString(strconv.Itoa(int(status)))
	w.b.WriteByte(' ')
	w.b.WriteString(meta)
	w.b.Write(crlf)
	w.wroteHeader = true
}

// Flush writes any buffered data to the underlying io.Writer.
//
// Flush writes the response header if it has not already been written.
// It writes a failure status code if one is not set.
func (w *ResponseWriter) Flush() error {
	if !w.wroteHeader {
		w.writeHeader(StatusTemporaryFailure)
	}
	// Write errors from writeHeader will be returned here.
	return w.b.Flush()
}
