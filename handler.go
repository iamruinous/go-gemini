package gemini

import (
	"context"
	"net/url"
	"strings"
)

// A Handler responds to a Gemini request.
//
// ServeGemini should write the response header and data to the ResponseWriter
// and then return. Returning signals that the request is finished; it is not
// valid to use the ResponseWriter after or concurrently with the completion
// of the ServeGemini call.
//
// Handlers should not modify the provided Request.
//
// If ServeGemini panics, the server (the caller of ServeGemini) assumes that
// the effect of the panic was isolated to the active request. It recovers
// the panic, logs a stack trace to the server error log, and closes the
// network connection. To abort a handler so the client sees an interrupted
// response but the server doesn't log an error, panic with the value
// ErrAbortHandler.
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

// RedirectHandler returns a request handler that redirects each request it
// receives to the given url using the given status code.
//
// The provided status code should be in the 3x range and is usually
// StatusRedirect or StatusPermanentRedirect.
func RedirectHandler(status Status, url string) Handler {
	return &redirectHandler{status, url}
}

type redirectHandler struct {
	status Status
	url    string
}

func (h *redirectHandler) ServeGemini(ctx context.Context, w ResponseWriter, r *Request) {
	w.WriteHeader(h.status, h.url)
}

// NotFoundHandler returns a simple request handler that replies to each
// request with a “51 Not found” reply.
func NotFoundHandler() Handler {
	return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNotFound, "Not found")
	})
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
