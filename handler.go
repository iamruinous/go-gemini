package gemini

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"time"
)

// A Handler responds to a Gemini request.
//
// ServeGemini should write the response header and data to the ResponseWriter
// and then return. Returning signals that the request is finished; it is not
// valid to use the ResponseWriter after or concurrently with the completion
// of the ServeGemini call. Handlers may also call ResponseWriter.Close to
// manually close the connection.
//
// The provided context is canceled when the client's connection is closed,
// when ResponseWriter.Close is called, or when the ServeGemini method returns.
//
// Handlers should not modify the provided Request.
type Handler interface {
	ServeGemini(context.Context, ResponseWriter, *Request)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions
// as Gemini handlers. If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler that calls f.
type HandlerFunc func(context.Context, ResponseWriter, *Request)

// ServeGemini calls f(ctx, w, r).
func (f HandlerFunc) ServeGemini(ctx context.Context, w ResponseWriter, r *Request) {
	f(ctx, w, r)
}

// StatusHandler returns a request handler that responds to each request
// with the provided status code and meta.
func StatusHandler(status Status, meta string) Handler {
	return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		w.WriteHeader(status, meta)
	})
}

// NotFoundHandler returns a simple request handler that replies to each
// request with a “51 Not found” reply.
func NotFoundHandler() Handler {
	return StatusHandler(StatusNotFound, "Not found")
}

// StripPrefix returns a handler that serves Gemini requests by removing the
// given prefix from the request URL's Path (and RawPath if set) and invoking
// the handler h. StripPrefix handles a request for a path that doesn't begin
// with prefix by replying with a Gemini 51 not found error. The prefix must
// match exactly: if the prefix in the request contains escaped characters the
// reply is also a Gemini 51 not found error.
func StripPrefix(prefix string, h Handler) Handler {
	if prefix == "" {
		return h
	}
	return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		p := strings.TrimPrefix(r.URL.Path, prefix)
		rp := strings.TrimPrefix(r.URL.RawPath, prefix)
		if len(p) < len(r.URL.Path) && (r.URL.RawPath == "" || len(rp) < len(r.URL.RawPath)) {
			r2 := new(Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = p
			r2.URL.RawPath = rp
			h.ServeGemini(ctx, w, r2)
		} else {
			w.WriteHeader(StatusNotFound, "Not found")
		}
	})
}

// TimeoutHandler returns a Handler that runs h with the given time limit.
//
// The new Handler calls h.ServeGemini to handle each request, but
// if a call runs for longer than its time limit, the handler responds with a
// 40 Temporary Failure error.
func TimeoutHandler(h Handler, dt time.Duration) Handler {
	return &timeoutHandler{
		h:  h,
		dt: dt,
	}
}

type timeoutHandler struct {
	h  Handler
	dt time.Duration
}

func (t *timeoutHandler) ServeGemini(ctx context.Context, w ResponseWriter, r *Request) {
	ctx, cancel := context.WithTimeout(ctx, t.dt)
	defer cancel()

	conn := w.Hijack()

	var b bytes.Buffer
	w.reset(nopCloser{&b})

	done := make(chan struct{})
	go func() {
		t.h.ServeGemini(ctx, w, r)
		close(done)
	}()

	select {
	case <-done:
		conn.Write(b.Bytes())
	case <-ctx.Done():
		w.reset(conn)
		w.WriteHeader(StatusTemporaryFailure, "Timeout")
	}
}
