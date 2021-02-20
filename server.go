package gemini

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// A Server defines parameters for running a Gemini server. The zero value for
// Server is a valid configuration.
type Server struct {
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":1965" (port 1965) is used.
	// See net.Dial for details of the address format.
	Addr string

	// The Handler to invoke.
	Handler Handler

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

	// GetCertificate returns a TLS certificate based on the given
	// hostname.
	//
	// If GetCertificate is nil or returns nil, then no certificate
	// will be used and the connection will be aborted.
	GetCertificate func(hostname string) (*tls.Certificate, error)

	// ErrorLog specifies an optional logger for errors accepting connections,
	// unexpected behavior from handlers, and underlying file system errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	listeners map[*net.Listener]struct{}
	conns     map[*net.Conn]struct{}
	done      int32
	mu        sync.Mutex
}

// ListenAndServe listens for requests at the server's configured address.
// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming connections.
//
// If srv.Addr is blank, ":1965" is used.
//
// ListenAndServe always returns a non-nil error. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) ListenAndServe() error {
	if atomic.LoadInt32(&srv.done) == 1 {
		return ErrServerClosed
	}

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

func (srv *Server) trackListener(l *net.Listener) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listeners == nil {
		srv.listeners = make(map[*net.Listener]struct{})
	}
	srv.listeners[l] = struct{}{}
}

func (srv *Server) deleteListener(l *net.Listener) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.listeners, l)
}

// Serve accepts incoming connections on the Listener l, creating a new
// service goroutine for each. The service goroutines read requests and
// then calls the appropriate Handler to reply to them.
//
// Serve always returns a non-nil error and closes l. After Shutdown or Close,
// the returned error is ErrServerClosed.
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()

	srv.trackListener(&l)
	defer srv.deleteListener(&l)

	if atomic.LoadInt32(&srv.done) == 1 {
		return ErrServerClosed
	}

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		rw, err := l.Accept()
		if err != nil {
			if atomic.LoadInt32(&srv.done) == 1 {
				return ErrServerClosed
			}
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

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(srv.listeners, ln)
	}
	return err
}

// Close immediately closes all active net.Listeners and connections.
// For a graceful shutdown, use Shutdown.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !atomic.CompareAndSwapInt32(&srv.done, 0, 1) {
		return ErrServerClosed
	}
	err := srv.closeListenersLocked()

	// Close active connections
	for conn := range srv.conns {
		(*conn).Close()
		delete(srv.conns, conn)
	}
	return err
}

func (srv *Server) numConns() int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.conns)
}

// shutdownPollInterval is how often we poll for quiescence
// during Server.Shutdown. This is lower during tests, to
// speed up tests.
// Ideally we could find a solution that doesn't involve polling,
// but which also doesn't have a high runtime cost (and doesn't
// involve any contentious mutexes), but that is left as an
// exercise for the reader.
var shutdownPollInterval = 500 * time.Millisecond

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners and then waiting indefinitely for connections
// to close and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
//
// When Shutdown is called, Serve, ListenAndServe, and
// ListenAndServeTLS immediately return ErrServerClosed. Make sure the
// program doesn't exit and waits instead for Shutdown to return.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (srv *Server) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&srv.done, 0, 1) {
		return ErrServerClosed
	}

	srv.mu.Lock()
	err := srv.closeListenersLocked()
	srv.mu.Unlock()

	// Wait for active connections to close
	ticker := time.NewTicker(shutdownPollInterval)
	defer ticker.Stop()
	for {
		if srv.numConns() == 0 {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (srv *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if srv.GetCertificate == nil {
		return nil, errors.New("gemini: GetCertificate is nil")
	}
	return srv.GetCertificate(h.ServerName)
}

func (srv *Server) trackConn(conn *net.Conn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.conns == nil {
		srv.conns = make(map[*net.Conn]struct{})
	}
	srv.conns[conn] = struct{}{}
}

func (srv *Server) deleteConn(conn *net.Conn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.conns, conn)
}

// respond responds to a connection.
func (srv *Server) respond(conn net.Conn) {
	defer conn.Close()

	defer func() {
		if err := recover(); err != nil && err != ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			srv.logf("gemini: panic serving %v: %v\n%s", conn.RemoteAddr(), err, buf)
		}
	}()

	srv.trackConn(&conn)
	defer srv.deleteConn(&conn)

	if d := srv.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := srv.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}

	w := newResponseWriter(conn)

	req, err := ReadRequest(conn)
	if err != nil {
		w.WriteHeader(StatusBadRequest, "Bad request")
		w.Flush()
		return
	}

	// Store information about the TLS connection
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		req.TLS = &state
		req.Host = state.ServerName
	}

	// Store remote address
	req.RemoteAddr = conn.RemoteAddr()

	h := srv.Handler
	if h == nil {
		w.WriteHeader(StatusNotFound, "Not found")
		w.Flush()
		return
	}

	// TODO: Allow configuring the server context
	ctx := context.Background()
	h.ServeGemini(ctx, w, req)
	w.Flush()
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
