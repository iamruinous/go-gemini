package gemini

import (
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
)

// The following code is modified from the net/http package.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ServeMux is a Gemini request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that
// most closely matches the URL.
//
// Patterns name fixed, rooted paths, like "/favicon.ico",
// or rooted subtrees, like "/images/" (note the trailing slash).
// Longer patterns take precedence over shorter ones, so that
// if there are handlers registered for both "/images/"
// and "/images/thumbnails/", the latter handler will be
// called for paths beginning "/images/thumbnails/" and the
// former will receive requests for any other paths in the
// "/images/" subtree.
//
// Note that since a pattern ending in a slash names a rooted subtree,
// the pattern "/" matches all paths not matched by other registered
// patterns, not just the URL with Path == "/".
//
// If a subtree has been registered and a request is received naming the
// subtree root without its trailing slash, ServeMux redirects that
// request to the subtree root (adding the trailing slash). This behavior can
// be overridden with a separate registration for the path without
// the trailing slash. For example, registering "/images/" causes ServeMux
// to redirect a request for "/images" to "/images/", unless "/images" has
// been registered separately.
//
// ServeMux also takes care of sanitizing the URL request path and
// redirecting any request containing . or .. elements or repeated slashes
// to an equivalent, cleaner URL.
type ServeMux struct {
	mu sync.RWMutex
	m  map[string]muxEntry
	es []muxEntry // slice of entries sorted from longest to shortest.
}

type muxEntry struct {
	r       Handler
	pattern string
}

// cleanPath returns the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		// Fast path for common case of p being the string we want:
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

// Find a handler on a handler map given a path string.
// Most-specific (longest) pattern wins.
func (mux *ServeMux) match(path string) Handler {
	// Check for exact match first.
	v, ok := mux.m[path]
	if ok {
		return v.r
	}

	// Check for longest valid match.  mux.es contains all patterns
	// that end in / sorted from longest to shortest.
	for _, e := range mux.es {
		if strings.HasPrefix(path, e.pattern) {
			return e.r
		}
	}
	return nil
}

// redirectToPathSlash determines if the given path needs appending "/" to it.
// This occurs when a handler for path + "/" was already registered, but
// not for path itself. If the path needs appending to, it creates a new
// URL, setting the path to u.Path + "/" and returning true to indicate so.
func (mux *ServeMux) redirectToPathSlash(path string, u *url.URL) (*url.URL, bool) {
	mux.mu.RLock()
	shouldRedirect := mux.shouldRedirectRLocked(path)
	mux.mu.RUnlock()
	if !shouldRedirect {
		return u, false
	}
	path = path + "/"
	u = &url.URL{Path: path, RawQuery: u.RawQuery}
	return u, true
}

// shouldRedirectRLocked reports whether the given path and host should be redirected to
// path+"/". This should happen if a handler is registered for path+"/" but
// not path -- see comments at ServeMux.
func (mux *ServeMux) shouldRedirectRLocked(path string) bool {
	if _, exist := mux.m[path]; exist {
		return false
	}

	n := len(path)
	if n == 0 {
		return false
	}
	if _, exist := mux.m[path+"/"]; exist {
		return path[n-1] != '/'
	}

	return false
}

// ServeGemini dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *ServeMux) ServeGemini(w ResponseWriter, r *Request) {
	path := cleanPath(r.URL.Path)

	// If the given path is /tree and its handler is not registered,
	// redirect for /tree/.
	if u, ok := mux.redirectToPathSlash(path, r.URL); ok {
		w.Header(StatusRedirect, u.String())
		return
	}

	if path != r.URL.Path {
		u := *r.URL
		u.Path = path
		w.Header(StatusRedirect, u.String())
		return
	}

	mux.mu.RLock()
	defer mux.mu.RUnlock()

	resp := mux.match(path)
	if resp == nil {
		w.Status(StatusNotFound)
		return
	}
	resp.ServeGemini(w, r)
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if handler == nil {
		panic("gemini: nil handler")
	}
	if _, exist := mux.m[pattern]; exist {
		panic("gemini: multiple registrations for " + pattern)
	}

	if mux.m == nil {
		mux.m = make(map[string]muxEntry)
	}
	e := muxEntry{handler, pattern}
	mux.m[pattern] = e
	if pattern[len(pattern)-1] == '/' {
		mux.es = appendSorted(mux.es, e)
	}
}

func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
	n := len(es)
	i := sort.Search(n, func(i int) bool {
		return len(es[i].pattern) < len(e.pattern)
	})
	if i == n {
		return append(es, e)
	}
	// we now know that i points at where we want to insert
	es = append(es, muxEntry{}) // try to grow the slice in place, any entry works.
	copy(es[i+1:], es[i:])      // move shorter entries down
	es[i] = e
	return es
}

// HandleFunc registers the handler function for the given pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	if handler == nil {
		panic("gemini: nil handler")
	}
	mux.Handle(pattern, HandlerFunc(handler))
}
