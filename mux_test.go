package gemini

import (
	"context"
	"io"
	"net/url"
	"testing"
)

type nopHandler struct{}

func (*nopHandler) ServeGemini(context.Context, ResponseWriter, *Request) {}

type nopResponseWriter struct {
	Status Status
	Meta   string
}

func (w *nopResponseWriter) WriteHeader(status Status, meta string) {
	w.Status = status
	w.Meta = meta
}

func (nopResponseWriter) SetMediaType(mediatype string) {}
func (nopResponseWriter) Write(b []byte) (int, error)   { return 0, io.EOF }
func (nopResponseWriter) Flush() error                  { return nil }

func TestMux(t *testing.T) {
	type Test struct {
		URL      string
		Pattern  string
		Redirect string
		NotFound bool
	}

	tests := []struct {
		Patterns []string
		Tests    []Test
	}{
		{
			Patterns: []string{"/a", "/b/", "/b/c/d", "/b/c/d/"},
			Tests: []Test{
				{
					URL:      "gemini://example.com",
					Redirect: "gemini://example.com/",
				},
				{
					URL:      "gemini://example.com/",
					NotFound: true,
				},
				{
					URL:      "gemini://example.com/c",
					NotFound: true,
				},
				{
					URL:     "gemini://example.com/a",
					Pattern: "/a",
				},
				{
					URL:      "gemini://example.com/a/",
					NotFound: true,
				},
				{
					URL:      "gemini://example.com/b",
					Redirect: "gemini://example.com/b/",
				},
				{
					URL:     "gemini://example.com/b/",
					Pattern: "/b/",
				},
				{
					URL:     "gemini://example.com/b/c",
					Pattern: "/b/",
				},
				{
					URL:     "gemini://example.com/b/c/d",
					Pattern: "/b/c/d",
				},
				{
					URL:     "gemini://example.com/b/c/d/e/",
					Pattern: "/b/c/d/",
				},
			},
		},
		{
			Patterns: []string{
				"/", "/a", "/b/",
				"example.com", "example.com/a", "example.com/b/",
				"*.example.com", "*.example.com/a", "*.example.com/b/",
			},
			Tests: []Test{
				{
					URL:     "gemini://example.net/",
					Pattern: "/",
				},
				{
					URL:     "gemini://example.net/a",
					Pattern: "/a",
				},
				{
					URL:      "gemini://example.net/b",
					Redirect: "gemini://example.net/b/",
				},
				{
					URL:     "gemini://example.net/b/",
					Pattern: "/b/",
				},
				{
					URL:     "gemini://example.com/",
					Pattern: "example.com",
				},
				{
					URL:      "gemini://example.com/b",
					Redirect: "gemini://example.com/b/",
				},
				{
					URL:     "gemini://example.com/b/",
					Pattern: "example.com/b/",
				},
				{
					URL:     "gemini://a.example.com/",
					Pattern: "*.example.com",
				},
				{
					URL:     "gemini://b.example.com/a",
					Pattern: "*.example.com/a",
				},
				{
					URL:      "gemini://c.example.com/b",
					Redirect: "gemini://c.example.com/b/",
				},
				{
					URL:     "gemini://d.example.com/b/",
					Pattern: "*.example.com/b/",
				},
			},
		},
		{
			Patterns: []string{"example.net", "*.example.org"},
			Tests: []Test{
				{
					// The following redirect occurs as a result of cleaning
					// the path provided to the Mux. This happens even if there
					// are no matching handlers.
					URL:      "gemini://example.com",
					Redirect: "gemini://example.com/",
				},
				{
					URL:      "gemini://example.com/",
					NotFound: true,
				},
				{
					URL:      "gemini://example.net",
					Redirect: "gemini://example.net/",
				},
				{
					URL:      "gemini://example.org/",
					NotFound: true,
				},
				{
					URL:      "gemini://gemini.example.org",
					Redirect: "gemini://gemini.example.org/",
				},
			},
		},
	}

	for _, test := range tests {
		type handler struct {
			nopHandler
			Pattern string
		}

		mux := &Mux{}
		for _, pattern := range test.Patterns {
			mux.Handle(pattern, &handler{
				Pattern: pattern,
			})
		}

		for _, test := range test.Tests {
			u, err := url.Parse(test.URL)
			if err != nil {
				panic(err)
			}

			req := &Request{URL: u}

			h := mux.Handler(req)

			if h, ok := h.(*handler); ok {
				if h.Pattern != test.Pattern {
					t.Errorf("wrong pattern for %q: expected %q, got %q", test.URL, test.Pattern, h.Pattern)
				}
				continue
			}

			// Check redirects and NotFounds
			w := &nopResponseWriter{}
			h.ServeGemini(context.Background(), w, req)

			switch w.Status {
			case StatusNotFound:
				if !test.NotFound {
					t.Errorf("expected pattern for %q, got NotFound", test.URL)
				}

			case StatusPermanentRedirect:
				if test.Redirect == "" {
					t.Errorf("expected pattern for %q, got redirect to %q", test.URL, w.Meta)
					break
				}

				res, err := url.Parse(test.Redirect)
				if err != nil {
					panic(err)
				}
				if w.Meta != res.String() {
					t.Errorf("bad redirect for %q: expected %q, got %q", test.URL, res.String(), w.Meta)
				}

			default:
				t.Errorf("unexpected response for %q: %d %s", test.URL, w.Status, w.Meta)
			}
		}
	}
}

func TestMuxMatch(t *testing.T) {
	type Match struct {
		URL string
		Ok  bool
	}

	tests := []struct {
		Pattern string
		Matches []Match
	}{
		{
			// hostname: *, path: /*
			Pattern: "/",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", true},
				{"gemini://example.com/path.gmi", true},
				{"gemini://example.com/path/", true},
				{"gemini://example.org/path", true},
				{"http://example.com/path", false},
				{"http://example.org/path", false},
			},
		},
		{
			// hostname: *, path: /path
			Pattern: "/path",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", false},
				{"gemini://example.com/path.gmi", false},
				{"gemini://example.com/path/", false},
				{"gemini://example.org/path", true},
				{"http://example.com/path", false},
				{"http://example.org/path", false},
			},
		},
		{
			// hostname: *, path: /subtree/*
			Pattern: "/subtree/",
			Matches: []Match{
				{"gemini://example.com/subtree/", true},
				{"gemini://example.com/subtree/nested/", true},
				{"gemini://example.com/subtree/nested/file", true},
				{"gemini://example.org/subtree/", true},
				{"gemini://example.org/subtree/nested/", true},
				{"gemini://example.org/subtree/nested/file", true},
				{"gemini://example.com/subtree", false},
				{"gemini://www.example.com/subtree/", true},
				{"http://example.com/subtree/", false},
			},
		},
		{
			// hostname: example.com, path: /*
			Pattern: "example.com",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", true},
				{"gemini://example.com/path.gmi", true},
				{"gemini://example.com/path/", true},
				{"gemini://example.org/path", false},
				{"http://example.com/path", false},
				{"http://example.org/path", false},
			},
		},
		{
			// hostname: example.com, path: /path
			Pattern: "example.com/path",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", false},
				{"gemini://example.com/path.gmi", false},
				{"gemini://example.com/path/", false},
				{"gemini://example.org/path", false},
				{"http://example.com/path", false},
				{"http://example.org/path", false},
			},
		},
		{
			// hostname: example.com, path: /subtree/*
			Pattern: "example.com/subtree/",
			Matches: []Match{
				{"gemini://example.com/subtree/", true},
				{"gemini://example.com/subtree/nested/", true},
				{"gemini://example.com/subtree/nested/file", true},
				{"gemini://example.org/subtree/", false},
				{"gemini://example.org/subtree/nested/", false},
				{"gemini://example.org/subtree/nested/file", false},
				{"gemini://example.com/subtree", false},
				{"gemini://www.example.com/subtree/", false},
				{"http://example.com/subtree/", false},
			},
		},
		{
			// scheme: gemini, hostname: *.example.com, path: /*
			Pattern: "*.example.com",
			Matches: []Match{
				{"gemini://mail.example.com/", true},
				{"gemini://www.example.com/index.gmi", true},
				{"gemini://example.com/", false},
				{"gemini://a.b.example.com/", false},
				{"http://www.example.com/", false},
			},
		},
	}

	for _, test := range tests {
		h := &nopHandler{}
		var mux Mux
		mux.Handle(test.Pattern, h)

		for _, match := range test.Matches {
			u, err := url.Parse(match.URL)
			if err != nil {
				panic(err)
			}
			got := mux.Handler(&Request{URL: u})
			if match.Ok {
				if h != got {
					t.Errorf("expected %s to match %s", test.Pattern, match.URL)
				}
			} else {
				if h == got {
					t.Errorf("expected %s not to match %s", test.Pattern, match.URL)
				}
			}
		}
	}
}
