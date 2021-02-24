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
		resp.body = newBufReadCloser(br, r)
	} else {
		resp.body = nopReadCloser{}
		r.Close()
	}
	return resp, nil
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
type ResponseWriter struct {
	bw          *bufio.Writer
	cl          io.Closer
	mediatype   string
	wroteHeader bool
	bodyAllowed bool
	hijacked    bool
	conn        net.Conn
}

func newResponseWriter(w io.WriteCloser) *ResponseWriter {
	return &ResponseWriter{
		bw: bufio.NewWriter(w),
		cl: w,
	}
}

func (w *ResponseWriter) reset(wc io.WriteCloser) {
	w.bw.Reset(wc)
	*w = ResponseWriter{
		bw: w.bw,
		cl: wc,
	}
}

// SetMediaType sets the media type that will be sent by Write for a
// successful response. If no media type is set, a default of
// "text/gemini; charset=utf-8" will be used.
//
// Setting the media type after a call to Write or WriteHeader has
// no effect.
func (w *ResponseWriter) SetMediaType(mediatype string) {
	w.mediatype = mediatype
}

// Write writes the data to the connection as part of a Gemini response.
//
// If WriteHeader has not yet been called, Write calls WriteHeader with
// StatusSuccess and the media type set in SetMediaType before writing the data.
// If no media type was set, Write uses a default media type of
// "text/gemini; charset=utf-8".
func (w *ResponseWriter) Write(b []byte) (int, error) {
	if w.hijacked {
		return 0, ErrHijacked
	}
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
func (w *ResponseWriter) WriteHeader(status Status, meta string) {
	if w.hijacked {
		return
	}
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

// Flush sends any buffered data to the client.
func (w *ResponseWriter) Flush() error {
	if w.hijacked {
		return ErrHijacked
	}
	if !w.wroteHeader {
		w.WriteHeader(StatusTemporaryFailure, "Temporary failure")
	}
	// Write errors from WriteHeader will be returned here.
	return w.bw.Flush()
}

// Close closes the connection.
// Any blocked Write operations will be unblocked and return errors.
func (w *ResponseWriter) Close() error {
	if w.hijacked {
		return ErrHijacked
	}
	return w.cl.Close()
}

// Conn returns the underlying network connection.
// To take over the connection, use Hijack.
func (w *ResponseWriter) Conn() net.Conn {
	return w.conn
}

// TLS returns information about the underlying TLS connection.
func (w *ResponseWriter) TLS() *tls.ConnectionState {
	if tlsConn, ok := w.conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		return &state
	}
	return nil
}

// Hijack lets the caller take over the connection.
// After a call to Hijack the Gemini server library
// will not do anything else with the connection.
// It becomes the caller's responsibility to manage
// and close the connection.
//
// The returned net.Conn may have read or write deadlines
// already set, depending on the configuration of the
// Server. It is the caller's responsibility to set
// or clear those deadlines as needed.
func (w *ResponseWriter) Hijack() net.Conn {
	w.hijacked = true
	return w.conn
}
