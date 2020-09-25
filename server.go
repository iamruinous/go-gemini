package gemini

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server is a Gemini server.
type Server struct {
	// Addr specifies the address that the server should listen on.
	// If Addr is empty, the server will listen on the address ":1965".
	Addr string

	// Certificate provides a TLS certificate for use by the server.
	// Using a self-signed certificate is recommended.
	Certificate tls.Certificate

	// Handler specifies the Handler for requests.
	// If Handler is not set, the server will error.
	Handler Handler
}

// ListenAndServe listens for requests at the server's configured address.
func (s *Server) ListenAndServe() error {
	addr := s.Addr

	if addr == "" {
		addr = ":1965"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{s.Certificate},
		ClientAuth:         tls.RequestClientCert,
	}
	tlsListener := tls.NewListener(ln, config)
	return s.Serve(tlsListener)
}

// Serve listens for requests on the provided listener.
func (s *Server) Serve(l net.Listener) error {
	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		rw, err := l.Accept()
		if err != nil {
			// If this is a temporary error, sleep
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("gemini: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			// Otherwise, return the error
			return err
		}

		tempDelay = 0
		go s.respond(rw)
	}
}

// ResponseWriter is used by a Gemini handler to construct a Gemini response.
type ResponseWriter struct {
	w           *bufio.Writer
	bodyAllowed bool
}

func newResponseWriter(conn net.Conn) *ResponseWriter {
	return &ResponseWriter{
		w: bufio.NewWriter(conn),
	}
}

// WriteHeader writes the response header.
//
// Meta contains more information related to the response status.
// For successful responses, Meta should contain the mimetype of the response.
// For failure responses, Meta should contain a short description of the failure.
// Meta should not be longer than 1024 bytes.
func (r *ResponseWriter) WriteHeader(status int, meta string) {
	r.w.WriteString(strconv.Itoa(status))
	r.w.WriteByte(' ')
	r.w.WriteString(meta)
	r.w.Write(crlf)

	// Only allow body to be written on successful status codes.
	if status/10 == StatusClassSuccess {
		r.bodyAllowed = true
	}
}

// Write writes the response body.
// If the response status does not allow for a response body, Write returns
// ErrBodyNotAllowed.
// WriteHeader must be called before Write.
func (r *ResponseWriter) Write(b []byte) (int, error) {
	if !r.bodyAllowed {
		return 0, ErrBodyNotAllowed
	}
	return r.w.Write(b)
}

// respond responds to a connection.
func (s *Server) respond(conn net.Conn) {
	r := bufio.NewReader(conn)
	rw := newResponseWriter(conn)
	// Read requested URL
	rawurl, err := r.ReadString('\r')
	if err != nil {
		return
	}
	// Read terminating line feed
	if b, err := r.ReadByte(); err != nil {
		return
	} else if b != '\n' {
		rw.WriteHeader(StatusBadRequest, "Bad request")
	}
	// Trim carriage return
	rawurl = rawurl[:len(rawurl)-1]
	// Ensure URL is valid
	if len(rawurl) > 1024 {
		rw.WriteHeader(StatusBadRequest, "Requested URL exceeds 1024 bytes")
	} else if url, err := url.Parse(rawurl); err != nil || url.User != nil {
		// Note that we return an error status if User is specified in the URL
		rw.WriteHeader(StatusBadRequest, "Requested URL is invalid")
	} else {
		// Gather information about the request
		req := &Request{
			URL:        url,
			RemoteAddr: conn.RemoteAddr(),
			TLS:        conn.(*tls.Conn).ConnectionState(),
		}
		s.Handler.Serve(rw, req)
	}
	rw.w.Flush()
	conn.Close()
}

// A Handler responds to a Gemini request.
type Handler interface {
	// Serve accepts a Request and constructs a Response.
	Serve(*ResponseWriter, *Request)
}

// ServeMux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that most closesly matches
// the URL.
type ServeMux struct {
	entries []muxEntry
}

type muxEntry struct {
	u       *url.URL
	handler Handler
}

func (m *ServeMux) match(url *url.URL) Handler {
	for _, e := range m.entries {
		if (e.u.Scheme == "" || url.Scheme == e.u.Scheme) &&
			(e.u.Host == "" || url.Host == e.u.Host) &&
			strings.HasPrefix(url.Path, e.u.Path) {
			return e.handler
		}
	}
	return nil
}

// Handle registers a Handler for the given pattern.
func (m *ServeMux) Handle(pattern string, handler Handler) {
	url, err := url.Parse(pattern)
	if err != nil {
		panic(err)
	}
	e := muxEntry{
		url,
		handler,
	}
	m.entries = appendSorted(m.entries, e)
}

// HandleFunc registers a HandlerFunc for the given pattern.
func (m *ServeMux) HandleFunc(pattern string, handlerFunc func(*ResponseWriter, *Request)) {
	handler := HandlerFunc(handlerFunc)
	m.Handle(pattern, handler)
}

// Serve responds to the request with the appropriate handler.
func (m *ServeMux) Serve(rw *ResponseWriter, req *Request) {
	h := m.match(req.URL)
	if h == nil {
		rw.WriteHeader(StatusNotFound, "Not found")
		return
	}
	h.Serve(rw, req)
}

// appendSorted appends the entry e in the proper place in entries.
func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
	n := len(es)
	// sort by length
	i := sort.Search(n, func(i int) bool {
		// Sort entries by length.
		// - Entries with a scheme take preference over entries without.
		// - Entries with a host take preference over entries without.
		// - Longer paths take preference over shorter paths.
		//
		// Long version:
		// if es[i].scheme != "" {
		// 	if e.scheme == "" {
		// 		return false
		// 	}
		// 	return len(es[i].scheme) < len(e.scheme)
		// }
		// if es[i].host != "" {
		// 	if e.host == "" {
		// 		return false
		// 	}
		// 	return len(es[i].host) < len(e.host)
		// }
		// return len(es[i].path) < len(e.path)

		// Condensed version:
		return (es[i].u.Scheme == "" || (e.u.Scheme != "" && len(es[i].u.Scheme) < len(e.u.Scheme))) &&
			(es[i].u.Host == "" || (e.u.Host != "" && len(es[i].u.Host) < len(e.u.Host))) &&
			len(es[i].u.Path) < len(e.u.Path)
	})
	if i == n {
		return append(es, e)
	}
	// we now know that i points at where we want to insert
	es = append(es, muxEntry{}) // try to grow the slice in place, any entry works.
	copy(es[i+1:], es[i:])      // Move shorter entries down
	es[i] = e
	return es
}

// A wrapper around a bare function that implements Handler.
type HandlerFunc func(*ResponseWriter, *Request)

func (f HandlerFunc) Serve(rw *ResponseWriter, req *Request) {
	f(rw, req)
}
