package gemini

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strconv"
)

// The default media type for responses.
const defaultMediaType = "text/gemini; charset=utf-8"

// Response represents the response from a Gemini request.
//
// The Client returns Responses from servers once the response
// header has been received. The response body is streamed on demand
// as the response is read. If the network connection fails or the server
// terminates the response, Read calls return an error.
//
// It is the caller's responsibility to close the response.
type Response struct {
	// Status contains the response status code.
	Status Status

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the media type of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	body io.ReadCloser
	conn net.Conn
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
	resp.Status = Status(status)

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
	if resp.Status.Class() == StatusSuccess && meta == "" {
		// Use default media type
		meta = defaultMediaType
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrInvalidResponse
	}

	if resp.Status.Class() == StatusSuccess {
		resp.body = newReadCloserBody(br, rc)
	} else {
		resp.body = nopReadCloser{}
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

// Read reads data from the response body.
// The response body is streamed on demand as Read is called.
func (r *Response) Read(p []byte) (n int, err error) {
	return r.body.Read(p)
}

// Close closes the response body.
func (r *Response) Close() error {
	return r.body.Close()
}

// Conn returns the network connection on which the response was received.
func (r *Response) Conn() net.Conn {
	return r.conn
}

// TLS returns information about the TLS connection on which the
// response was received.
func (r *Response) TLS() *tls.ConnectionState {
	if tlsConn, ok := r.conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		return &state
	}
	return nil
}

// A ResponseWriter interface is used by a Gemini handler to construct
// a Gemini response.
//
// A ResponseWriter may not be used after the Handler.ServeGemini method
// has returned.
type ResponseWriter interface {
	// SetMediaType sets the media type that will be sent by Write for a
	// successful response. If no media type is set, a default of
	// "text/gemini; charset=utf-8" will be used.
	//
	// Setting the media type after a call to Write or WriteHeader has
	// no effect.
	SetMediaType(string)

	// Write writes the data to the connection as part of a Gemini response.
	//
	// If WriteHeader has not yet been called, Write calls WriteHeader with
	// StatusSuccess and the media type set in SetMediaType before writing the data.
	// If no media type was set, Write uses a default media type of
	// "text/gemini; charset=utf-8".
	Write([]byte) (int, error)

	// WriteHeader sends a Gemini response header with the provided
	// status code and meta.
	//
	// If WriteHeader is not called explicitly, the first call to Write
	// will trigger an implicit call to WriteHeader with a successful
	// status code and the media type set in SetMediaType.
	//
	// The provided code must be a valid Gemini status code.
	// The provided meta must not be longer than 1024 bytes.
	// Only one header may be written.
	WriteHeader(status Status, meta string)

	// Flush sends any buffered data to the client.
	Flush() error

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error
}

type responseWriter struct {
	b           *bufio.Writer
	closer      io.Closer
	mediatype   string
	wroteHeader bool
	bodyAllowed bool
}

// NewResponseWriter returns a ResponseWriter that uses the provided io.WriteCloser.
func NewResponseWriter(wc io.WriteCloser) ResponseWriter {
	return newResponseWriter(wc)
}

func newResponseWriter(wc io.WriteCloser) *responseWriter {
	return &responseWriter{
		b:      bufio.NewWriter(wc),
		closer: wc,
	}
}

func (w *responseWriter) SetMediaType(mediatype string) {
	w.mediatype = mediatype
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		meta := w.mediatype
		if meta == "" {
			// Use default media type
			meta = defaultMediaType
		}
		w.WriteHeader(StatusSuccess, meta)
	}
	if !w.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return w.b.Write(b)
}

func (w *responseWriter) WriteHeader(status Status, meta string) {
	if w.wroteHeader {
		return
	}

	if status.Class() == StatusSuccess {
		w.bodyAllowed = true
	}

	w.b.WriteString(strconv.Itoa(int(status)))
	w.b.WriteByte(' ')
	w.b.WriteString(meta)
	w.b.Write(crlf)
	w.wroteHeader = true
}

func (w *responseWriter) Flush() error {
	if !w.wroteHeader {
		w.WriteHeader(StatusTemporaryFailure, "Temporary failure")
	}
	// Write errors from WriteHeader will be returned here.
	return w.b.Flush()
}

func (w *responseWriter) Close() error {
	return w.closer.Close()
}
