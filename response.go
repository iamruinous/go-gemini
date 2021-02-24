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
	status Status
	meta   string
	body   io.ReadCloser
	conn   net.Conn
}

// ReadResponse reads a Gemini response from the provided io.ReadCloser.
func ReadResponse(r io.ReadCloser) (*Response, error) {
	resp := &Response{}
	br := bufio.NewReader(r)

	// Read the status
	statusB := make([]byte, 2)
	if _, err := br.Read(statusB); err != nil {
		return nil, err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	resp.status = Status(status)

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
	if resp.status.Class() == StatusSuccess && meta == "" {
		// Use default media type
		meta = defaultMediaType
	}
	resp.meta = meta

	// Read terminating newline
	if b, err := br.ReadByte(); err != nil {
		return nil, err
	} else if b != '\n' {
		return nil, ErrInvalidResponse
	}

	if resp.status.Class() == StatusSuccess {
		resp.body = newBufReadCloser(br, r)
	} else {
		resp.body = nopReadCloser{}
		r.Close()
	}
	return resp, nil
}

// Status returns the response status code.
func (r *Response) Status() Status {
	return r.status
}

// Meta returns the response meta.
// For successful responses, the meta should contain the media type of the response.
// For failure responses, the meta should contain a short description of the failure.
func (r *Response) Meta() string {
	return r.meta
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
	SetMediaType(mediatype string)

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
	// Any blocked Write operations will be unblocked and return errors.
	Close() error
}

type responseWriter struct {
	bw          *bufio.Writer
	cl          io.Closer
	mediatype   string
	wroteHeader bool
	bodyAllowed bool
}

func newResponseWriter(w io.WriteCloser) *responseWriter {
	return &responseWriter{
		bw: bufio.NewWriter(w),
		cl: w,
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
	return w.bw.Write(b)
}

func (w *responseWriter) WriteHeader(status Status, meta string) {
	if w.wroteHeader {
		return
	}

	if status.Class() == StatusSuccess {
		w.bodyAllowed = true
	}

	w.bw.WriteString(strconv.Itoa(int(status)))
	w.bw.WriteByte(' ')
	w.bw.WriteString(meta)
	w.bw.Write(crlf)
	w.wroteHeader = true
}

func (w *responseWriter) Flush() error {
	if !w.wroteHeader {
		w.WriteHeader(StatusTemporaryFailure, "Temporary failure")
	}
	// Write errors from WriteHeader will be returned here.
	return w.bw.Flush()
}

func (w *responseWriter) Close() error {
	return w.cl.Close()
}
