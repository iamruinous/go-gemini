package gemini

import (
	"context"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
)

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
// Patterns may also contain schemes and hostnames.
// Wildcard patterns can be used to match multiple hostnames (e.g. "*.example.com").
//
// The following are examples of valid patterns, along with the scheme,
// hostname, and path that they match.
//
//     Pattern                      │ Scheme │ Hostname │ Path
//     ─────────────────────────────┼────────┼──────────┼─────────────
//     /file                        │ gemini │ *        │ /file
//     /directory/                  │ gemini │ *        │ /directory/*
//     hostname/file                │ gemini │ hostname │ /file
//     hostname/directory/          │ gemini │ hostname │ /directory/*
//     scheme://hostname/file       │ scheme │ hostname │ /file
//     scheme://hostname/directory/ │ scheme │ hostname │ /directory/*
//     //hostname/file              │ *      │ hostname │ /file
//     //hostname/directory/        │ *      │ hostname │ /directory/*
//     scheme:///file               │ scheme │ *        │ /file
//     scheme:///directory/         │ scheme │ *        │ /directory/*
//     ///file                      │ *      │ *        │ /file
//     ///directory/                │ *      │ *        │ /directory/*
//
// A pattern without a hostname will match any hostname.
// If a pattern begins with "//", it will match any scheme.
// Otherwise, a pattern with no scheme is treated as though it has a
// scheme of "gemini".
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
	m  map[muxKey]Handler
	es []muxEntry // slice of entries sorted from longest to shortest
}

type muxKey struct {
	scheme string
	host   string
	path   string
}

type muxEntry struct {
	handler Handler
	key     muxKey
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
func (mux *ServeMux) match(key muxKey) Handler {
	// Check for exact match first.
	if r, ok := mux.m[key]; ok {
		return r
	} else if r, ok := mux.m[muxKey{"", key.host, key.path}]; ok {
		return r
	} else if r, ok := mux.m[muxKey{key.scheme, "", key.path}]; ok {
		return r
	} else if r, ok := mux.m[muxKey{"", "", key.path}]; ok {
		return r
	}

	// Check for longest valid match.  mux.es contains all patterns
	// that end in / sorted from longest to shortest.
	for _, e := range mux.es {
		if (e.key.scheme == "" || key.scheme == e.key.scheme) &&
			(e.key.host == "" || key.host == e.key.host) &&
			strings.HasPrefix(key.path, e.key.path) {
			return e.handler
		}
	}
	return nil
}

// redirectToPathSlash determines if the given path needs appending "/" to it.
// This occurs when a handler for path + "/" was already registered, but
// not for path itself. If the path needs appending to, it creates a new
// URL, setting the path to u.Path + "/" and returning true to indicate so.
func (mux *ServeMux) redirectToPathSlash(key muxKey, u *url.URL) (*url.URL, bool) {
	mux.mu.RLock()
	shouldRedirect := mux.shouldRedirectRLocked(key)
	mux.mu.RUnlock()
	if !shouldRedirect {
		return u, false
	}
	return u.ResolveReference(&url.URL{Path: key.path + "/"}), true
}

// shouldRedirectRLocked reports whether the given path and host should be redirected to
// path+"/". This should happen if a handler is registered for path+"/" but
// not path -- see comments at ServeMux.
func (mux *ServeMux) shouldRedirectRLocked(key muxKey) bool {
	if _, exist := mux.m[key]; exist {
		return false
	}

	n := len(key.path)
	if n == 0 {
		return false
	}
	if _, exist := mux.m[muxKey{key.scheme, key.host, key.path + "/"}]; exist {
		return key.path[n-1] != '/'
	}
	return false
}

func getWildcard(hostname string) (string, bool) {
	if net.ParseIP(hostname) == nil {
		split := strings.SplitN(hostname, ".", 2)
		if len(split) == 2 {
			return "*." + split[1], true
		}
	}
	return "", false
}

// Handler returns the handler to use for the given request, consulting
// r.URL.Scheme, r.URL.Host, and r.URL.Path. It always returns a non-nil handler. If
// the path is not in its canonical form, the handler will be an
// internally-generated handler that redirects to the canonical path. If the
// host contains a port, it is ignored when matching handlers.
func (mux *ServeMux) Handler(r *Request) Handler {
	scheme := r.URL.Scheme
	host := r.URL.Hostname()
	path := cleanPath(r.URL.Path)

	// If the given path is /tree and its handler is not registered,
	// redirect for /tree/.
	if u, ok := mux.redirectToPathSlash(muxKey{scheme, host, path}, r.URL); ok {
		return StatusHandler(StatusPermanentRedirect, u.String())
	}

	if path != r.URL.Path {
		u := *r.URL
		u.Path = path
		return StatusHandler(StatusPermanentRedirect, u.String())
	}

	mux.mu.RLock()
	defer mux.mu.RUnlock()

	h := mux.match(muxKey{scheme, host, path})
	if h == nil {
		// Try wildcard
		if wildcard, ok := getWildcard(host); ok {
			h = mux.match(muxKey{scheme, wildcard, path})
		}
	}
	if h == nil {
		h = NotFoundHandler()
	}
	return h
}

// ServeGemini dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *ServeMux) ServeGemini(ctx context.Context, w *ResponseWriter, r *Request) {
	h := mux.Handler(r)
	h.ServeGemini(ctx, w, r)
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		panic("gemini: invalid pattern")
	}
	if handler == nil {
		panic("gemini: nil handler")
	}

	mux.mu.Lock()
	defer mux.mu.Unlock()

	var key muxKey
	if strings.HasPrefix(pattern, "//") {
		// match any scheme
		key.scheme = ""
		pattern = pattern[2:]
	} else {
		// extract scheme
		cut := strings.Index(pattern, "://")
		if cut == -1 {
			// default scheme of gemini
			key.scheme = "gemini"
		} else {
			key.scheme = pattern[:cut]
			pattern = pattern[cut+3:]
		}
	}

	// extract hostname and path
	cut := strings.Index(pattern, "/")
	if cut == -1 {
		key.host = pattern
		key.path = "/"
	} else {
		key.host = pattern[:cut]
		key.path = pattern[cut:]
	}

	// strip port from hostname
	if hostname, _, err := net.SplitHostPort(key.host); err == nil {
		key.host = hostname
	}

	if _, exist := mux.m[key]; exist {
		panic("gemini: multiple registrations for " + pattern)
	}

	if mux.m == nil {
		mux.m = make(map[muxKey]Handler)
	}
	mux.m[key] = handler
	e := muxEntry{handler, key}
	if key.path[len(key.path)-1] == '/' {
		mux.es = appendSorted(mux.es, e)
	}
}

func appendSorted(es []muxEntry, e muxEntry) []muxEntry {
	n := len(es)
	i := sort.Search(n, func(i int) bool {
		return len(es[i].key.scheme) < len(e.key.scheme) ||
			len(es[i].key.host) < len(es[i].key.host) ||
			len(es[i].key.path) < len(e.key.path)
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
func (mux *ServeMux) HandleFunc(pattern string, handler HandlerFunc) {
	mux.Handle(pattern, handler)
}
