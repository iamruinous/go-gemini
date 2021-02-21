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

	listeners map[*net.Listener]context.CancelFunc
	conns     map[*net.Conn]context.CancelFunc
	doneChan  chan struct{}
	closed    int32
	mu        sync.Mutex
}

// done returns a channel that's closed when the server has finished closing.
func (srv *Server) done() chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.doneLocked()
}

func (srv *Server) doneLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

// tryFinishShutdown closes srv.done() if there are no active listeners or requests.
func (srv *Server) tryFinishShutdown() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.listeners) == 0 && len(srv.conns) == 0 {
		done := srv.doneLocked()
		select {
		case <-done:
		default:
			close(done)
		}
	}
}

// Close immediately closes all active net.Listeners and connections.
// For a graceful shutdown, use Shutdown.
func (srv *Server) Close() error {
	if !atomic.CompareAndSwapInt32(&srv.closed, 0, 1) {
		return ErrServerClosed
	}

	// Close active listeners and connections.
	srv.mu.Lock()
	for _, cancel := range srv.listeners {
		cancel()
	}
	for _, cancel := range srv.conns {
		cancel()
	}
	srv.mu.Unlock()

	select {
	case <-srv.done():
		return nil
	}
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners and then waiting indefinitely for connections
// to close and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error.
//
// When Shutdown is called, Serve and ListenAndServer immediately
// return ErrServerClosed. Make sure the program doesn't exit and
// waits instead for Shutdown to return.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (srv *Server) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&srv.closed, 0, 1) {
		return ErrServerClosed
	}

	// Close active listeners.
	srv.mu.Lock()
	for _, cancel := range srv.listeners {
		cancel()
	}
	srv.mu.Unlock()

	// Wait for active connections to finish.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-srv.done():
		return nil
	}
}

// ListenAndServe listens for requests at the server's configured address.
// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle requests on incoming connections.
//
// If srv.Addr is blank, ":1965" is used.
//
// ListenAndServe always returns a non-nil error. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	if atomic.LoadInt32(&srv.closed) == 1 {
		return ErrServerClosed
	}

	addr := srv.Addr
	if addr == "" {
		addr = ":1965"
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	l = tls.NewListener(l, &tls.Config{
		ClientAuth:     tls.RequestClientCert,
		MinVersion:     tls.VersionTLS12,
		GetCertificate: srv.getCertificate,
	})
	return srv.Serve(ctx, l)
}

func (srv *Server) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if srv.GetCertificate == nil {
		return nil, errors.New("gemini: GetCertificate is nil")
	}
	return srv.GetCertificate(h.ServerName)
}

func (srv *Server) trackListener(l *net.Listener, cancel context.CancelFunc) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listeners == nil {
		srv.listeners = make(map[*net.Listener]context.CancelFunc)
	}
	srv.listeners[l] = cancel
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
func (srv *Server) Serve(ctx context.Context, l net.Listener) error {
	defer l.Close()

	if atomic.LoadInt32(&srv.closed) == 1 {
		return ErrServerClosed
	}

	lnctx, cancel := context.WithCancel(ctx)
	defer cancel()

	srv.trackListener(&l, cancel)
	defer srv.tryFinishShutdown()
	defer srv.deleteListener(&l)

	errch := make(chan error, 1)
	go func() {
		errch <- srv.serve(ctx, l)
	}()

	select {
	case <-lnctx.Done():
		return lnctx.Err()
	case err := <-errch:
		return err
	}
}

func (srv *Server) serve(ctx context.Context, l net.Listener) error {
	// how long to sleep on accept failure
	var tempDelay time.Duration

	for {
		rw, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
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

			return err
		}

		tempDelay = 0
		go srv.serveConn(ctx, rw)
	}
}

func (srv *Server) trackConn(conn *net.Conn, cancel context.CancelFunc) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.conns == nil {
		srv.conns = make(map[*net.Conn]context.CancelFunc)
	}
	srv.conns[conn] = cancel
}

func (srv *Server) deleteConn(conn *net.Conn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.conns, conn)
}

// serveConn serves a Gemini response over the provided connection.
// It closes the connection when the response has been completed.
func (srv *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if atomic.LoadInt32(&srv.closed) == 1 {
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	srv.trackConn(&conn, cancel)
	defer srv.tryFinishShutdown()
	defer srv.deleteConn(&conn)

	defer func() {
		if err := recover(); err != nil && err != ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			srv.logf("gemini: panic serving %v: %v\n%s", conn.RemoteAddr(), err, buf)
		}
	}()

	if d := srv.ReadTimeout; d != 0 {
		conn.SetReadDeadline(time.Now().Add(d))
	}
	if d := srv.WriteTimeout; d != 0 {
		conn.SetWriteDeadline(time.Now().Add(d))
	}

	done := make(chan struct{})
	go func() {
		srv.respond(ctx, conn)
		close(done)
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func (srv *Server) respond(ctx context.Context, conn net.Conn) {
	w := newResponseWriter(conn)
	defer w.Flush()

	req, err := ReadRequest(conn)
	if err != nil {
		w.WriteHeader(StatusBadRequest, "Bad request")
		return
	}

	// Store the TLS connection state
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
		return
	}

	h.ServeGemini(ctx, w, req)
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
