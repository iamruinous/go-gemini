package gemini

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"git.sr.ht/~adnano/go-gemini/certificate"
)

// A Server defines parameters for running a Gemini server. The zero value for
// Server is a valid configuration.
type Server struct {
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":1965" (port 1965) is used.
	// See net.Dial for details of the address format.
	Addr string

	// ReadTimeout is the maximum duration for reading the entire
	// request.
	//
	// A ReadTimeout of zero means no timeout.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response.
	//
	// A WriteTimeout of zero means no timeout.
	WriteTimeout time.Duration

	// Certificates contains one or more certificates to present to the
	// other side of the connection.
	Certificates certificate.Dir

	// GetCertificate, if not nil, will be called to retrieve a new certificate
	// if the current one is expired or missing.
	GetCertificate func(hostname string) (tls.Certificate, error)

	// ErrorLog specifies an optional logger for errors accepting connections,
	// unexpected behavior from handlers, and underlying file system errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	// registered handlers
	handlers map[handlerKey]Handler
	hosts    map[string]bool
}

type handlerKey struct {
	scheme   string
	hostname string
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
//
// The pattern must be in the form of "hostname" or "scheme://hostname".
// If no scheme is specified, a scheme of "gemini://" is implied.
// Wildcard patterns are supported (e.g. "*.example.com").
// To handle any hostname, use the wildcard pattern "*".
func (srv *Server) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if handler == nil {
		panic("gemini: nil responder")
	}
	if srv.handlers == nil {
		srv.handlers = map[handlerKey]Handler{}
		srv.hosts = map[string]bool{}
	}

	split := strings.SplitN(pattern, "://", 2)
	var key handlerKey
	if len(split) == 2 {
		key.scheme = split[0]
		key.hostname = split[1]
	} else {
		key.scheme = "gemini"
		key.hostname = split[0]
	}

	if _, ok := srv.handlers[key]; ok {
		panic("gemini: multiple registrations for " + pattern)
	}
	srv.handlers[key] = handler
	srv.hosts[key.hostname] = true
}

// HandleFunc registers the handler function for the given pattern.
func (srv *Server) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	srv.Handle(pattern, HandlerFunc(handler))
}

// ListenAndServe listens for requests at the server's configured address.
// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming connections.
//
// If srv.Addr is blank, ":1965" is used.
//
// TODO:
// ListenAndServe always returns a non-nil error. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":1965"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	return srv.Serve(tls.NewListener(ln, &tls.Config{
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     tls.VersionTLS12,
		GetCertificate: srv.getCertificate,
	}))
}

// Serve accepts incoming connections on the Listener l, creating a new
// service goroutine for each. The service goroutines read requests and
// then calls the appropriate Handler to reply to them.
//
// TODO:
// Serve always returns a non-nil error and closes l. After Shutdown or Close,
// the returned error is ErrServerClosed.
func (srv *Server) Serve(l net.Listener) error {
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
				srv.logf("gemini: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			// Otherwise, return the error
			return err
		}

		tempDelay = 0
		go srv.respond(rw)
	}
}

// getCertificate retrieves a certificate for the given client hello.
func (srv *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := srv.lookupCertificate(h.ServerName, h.ServerName)
	if err != nil {
		// Try wildcard
		wildcard := strings.SplitN(h.ServerName, ".", 2)
		if len(wildcard) == 2 {
			// Use the wildcard pattern as the hostname.
			hostname := "*." + wildcard[1]
			cert, err = srv.lookupCertificate(hostname, hostname)
		}
		// Try "*" wildcard
		if err != nil {
			// Use the server name as the hostname
			// since "*" is not a valid hostname.
			cert, err = srv.lookupCertificate("*", h.ServerName)
		}
	}
	return cert, err
}

// lookupCertificate retrieves the certificate for the given hostname,
// if and only if the provided pattern is registered.
// If no certificate is found in the certificate store or the certificate
// is expired, it calls GetCertificate to retrieve a new certificate.
func (srv *Server) lookupCertificate(pattern, hostname string) (*tls.Certificate, error) {
	if _, ok := srv.hosts[pattern]; !ok {
		return nil, errors.New("hostname not registered")
	}

	cert, ok := srv.Certificates.Lookup(hostname)
	if !ok || cert.Leaf != nil && cert.Leaf.NotAfter.Before(time.Now()) {
		if srv.GetCertificate != nil {
			cert, err := srv.GetCertificate(hostname)
			if err == nil {
				if err := srv.Certificates.Add(hostname, cert); err != nil {
					srv.logf("gemini: Failed to write new certificate for %s: %s", hostname, err)
				}
			}
			return &cert, err
		}
		return nil, errors.New("no certificate")
	}

	return &cert, nil
}

// respond responds to a connection.
func (srv *Server) respond(conn net.Conn) {
	defer conn.Close()
	if d := srv.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := srv.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}

	w := NewResponseWriter(conn)
	defer w.Flush()

	req, err := ReadRequest(conn)
	if err != nil {
		w.Status(StatusBadRequest)
		return
	}

	// Store information about the TLS connection
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		req.TLS = &state
		if len(req.TLS.PeerCertificates) > 0 {
			peerCert := req.TLS.PeerCertificates[0]
			// Store the TLS certificate
			req.Certificate = &tls.Certificate{
				Certificate: [][]byte{peerCert.Raw},
				Leaf:        peerCert,
			}
		}
	}

	// Store remote address
	req.RemoteAddr = conn.RemoteAddr()

	resp := srv.responder(req)
	if resp == nil {
		w.Status(StatusNotFound)
		return
	}

	resp.ServeGemini(w, req)
}

func (srv *Server) responder(r *Request) Handler {
	if h, ok := srv.handlers[handlerKey{r.URL.Scheme, r.URL.Hostname()}]; ok {
		return h
	}
	wildcard := strings.SplitN(r.URL.Hostname(), ".", 2)
	if len(wildcard) == 2 {
		if h, ok := srv.handlers[handlerKey{r.URL.Scheme, "*." + wildcard[1]}]; ok {
			return h
		}
	}
	if h, ok := srv.handlers[handlerKey{r.URL.Scheme, "*"}]; ok {
		return h
	}
	return nil
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// A Handler responds to a Gemini request.
//
// ServeGemini should write the response header and data to the ResponseWriter
// and then return. Returning signals that the request is finished; it is not
// valid to use the ResponseWriter after or concurrently with the completion
// of the ServeGemini call.
//
// Handlers should not modify the provided Request.
//
// TODO:
// If ServeGemini panics, the server (the caller of ServeGemini) assumes that
// the effect of the panic was isolated to the active request. It recovers
// the panic, logs a stack trace to the server error log, and closes the
// newtwork connection. To abort a handler so the client sees an interrupted
// response but the server doesn't log an error, panic with the value
// ErrAbortHandler.
type Handler interface {
	ServeGemini(ResponseWriter, *Request)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as Gemini handlers. If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeGemini calls f(w, r).
func (f HandlerFunc) ServeGemini(w ResponseWriter, r *Request) {
	f(w, r)
}
