package gemini

import (
	"context"
	"net/url"
	"testing"
)

type nopHandler struct{}

func (*nopHandler) ServeGemini(context.Context, *ResponseWriter, *Request) {}

func TestServeMuxMatch(t *testing.T) {
	type Match struct {
		URL string
		Ok  bool
	}

	tests := []struct {
		Pattern string
		Matches []Match
	}{
		{
			// scheme: gemini, hostname: *, path: /*
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
			// scheme: gemini, hostname: *, path: /path
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
			// scheme: gemini, hostname: *, path: /subtree/*
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
			// scheme: gemini, hostname: example.com, path: /*
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
			// scheme: gemini, hostname: example.com, path: /path
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
			// scheme: gemini, hostname: example.com, path: /subtree/*
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
			// scheme: http, hostname: example.com, path: /*
			Pattern: "http://example.com",
			Matches: []Match{
				{"http://example.com/path", true},
				{"http://example.com/", true},
				{"http://example.com/path.gmi", true},
				{"http://example.com/path/", true},
				{"http://example.org/path", false},
				{"gemini://example.com/path", false},
				{"gemini://example.org/path", false},
			},
		},
		{
			// scheme: http, hostname: example.com, path: /path
			Pattern: "http://example.com/path",
			Matches: []Match{
				{"http://example.com/path", true},
				{"http://example.com/", false},
				{"http://example.com/path.gmi", false},
				{"http://example.com/path/", false},
				{"http://example.org/path", false},
				{"gemini://example.com/path", false},
				{"gemini://example.org/path", false},
			},
		},
		{
			// scheme: http, hostname: example.com, path: /subtree/*
			Pattern: "http://example.com/subtree/",
			Matches: []Match{
				{"http://example.com/subtree/", true},
				{"http://example.com/subtree/nested/", true},
				{"http://example.com/subtree/nested/file", true},
				{"http://example.org/subtree/", false},
				{"http://example.org/subtree/nested/", false},
				{"http://example.org/subtree/nested/file", false},
				{"http://example.com/subtree", false},
				{"http://www.example.com/subtree/", false},
				{"gemini://example.com/subtree/", false},
			},
		},
		{
			// scheme: *, hostname: example.com, path: /*
			Pattern: "//example.com",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", true},
				{"gemini://example.com/path.gmi", true},
				{"gemini://example.com/path/", true},
				{"gemini://example.org/path", false},
				{"http://example.com/path", true},
				{"http://example.org/path", false},
			},
		},
		{
			// scheme: *, hostname: example.com, path: /path
			Pattern: "//example.com/path",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", false},
				{"gemini://example.com/path.gmi", false},
				{"gemini://example.com/path/", false},
				{"gemini://example.org/path", false},
				{"http://example.com/path", true},
				{"http://example.org/path", false},
			},
		},
		{
			// scheme: *, hostname: example.com, path: /subtree/*
			Pattern: "//example.com/subtree/",
			Matches: []Match{
				{"gemini://example.com/subtree/", true},
				{"gemini://example.com/subtree/nested/", true},
				{"gemini://example.com/subtree/nested/file", true},
				{"gemini://example.org/subtree/", false},
				{"gemini://example.org/subtree/nested/", false},
				{"gemini://example.org/subtree/nested/file", false},
				{"gemini://example.com/subtree", false},
				{"gemini://www.example.com/subtree/", false},
				{"http://example.com/subtree/", true},
			},
		},
		{
			// scheme: http, hostname: *, path: /*
			Pattern: "http://",
			Matches: []Match{
				{"http://example.com/path", true},
				{"http://example.com/", true},
				{"http://example.com/path.gmi", true},
				{"http://example.com/path/", true},
				{"http://example.org/path", true},
				{"gemini://example.com/path", false},
				{"gemini://example.org/path", false},
			},
		},
		{
			// scheme: http, hostname: *, path: /path
			Pattern: "http:///path",
			Matches: []Match{
				{"http://example.com/path", true},
				{"http://example.com/", false},
				{"http://example.com/path.gmi", false},
				{"http://example.com/path/", false},
				{"http://example.org/path", true},
				{"gemini://example.com/path", false},
				{"gemini://example.org/path", false},
			},
		},
		{
			// scheme: http, hostname: *, path: /subtree/*
			Pattern: "http:///subtree/",
			Matches: []Match{
				{"http://example.com/subtree/", true},
				{"http://example.com/subtree/nested/", true},
				{"http://example.com/subtree/nested/file", true},
				{"http://example.org/subtree/", true},
				{"http://example.org/subtree/nested/", true},
				{"http://example.org/subtree/nested/file", true},
				{"http://example.com/subtree", false},
				{"http://www.example.com/subtree/", true},
				{"gemini://example.com/subtree/", false},
			},
		},
		{
			// scheme: *, hostname: *, path: /*
			Pattern: "//",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", true},
				{"gemini://example.com/path.gmi", true},
				{"gemini://example.com/path/", true},
				{"gemini://example.org/path", true},
				{"http://example.com/path", true},
				{"http://example.org/path", true},
			},
		},
		{
			// scheme: *, hostname: *, path: /path
			Pattern: "///path",
			Matches: []Match{
				{"gemini://example.com/path", true},
				{"gemini://example.com/", false},
				{"gemini://example.com/path.gmi", false},
				{"gemini://example.com/path/", false},
				{"gemini://example.org/path", true},
				{"http://example.com/path", true},
				{"http://example.org/path", true},
			},
		},
		{
			// scheme: *, hostname: *, path: /subtree/*
			Pattern: "///subtree/",
			Matches: []Match{
				{"gemini://example.com/subtree/", true},
				{"gemini://example.com/subtree/nested/", true},
				{"gemini://example.com/subtree/nested/file", true},
				{"gemini://example.org/subtree/", true},
				{"gemini://example.org/subtree/nested/", true},
				{"gemini://example.org/subtree/nested/file", true},
				{"gemini://example.com/subtree", false},
				{"gemini://www.example.com/subtree/", true},
				{"http://example.com/subtree/", true},
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
		{
			// scheme: http, hostname: *.example.com, path: /*
			Pattern: "http://*.example.com",
			Matches: []Match{
				{"http://mail.example.com/", true},
				{"http://www.example.com/index.gmi", true},
				{"http://example.com/", false},
				{"http://a.b.example.com/", false},
				{"gemini://www.example.com/", false},
			},
		},
	}

	for i, test := range tests {
		h := &nopHandler{}
		var mux ServeMux
		mux.Handle(test.Pattern, h)

		for _, match := range tests[i].Matches {
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
