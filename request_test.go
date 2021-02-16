package gemini

import (
	"bufio"
	"io"
	"net/url"
	"strings"
	"testing"
)

// 1024 bytes
const maxURL = "gemini://example.net/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

func TestReadRequest(t *testing.T) {
	tests := []struct {
		Raw string
		URL *url.URL
		Err error
	}{
		{
			Raw: "gemini://example.com\r\n",
			URL: &url.URL{
				Scheme: "gemini",
				Host:   "example.com",
			},
		},
		{
			Raw: "http://example.org/path/?query#fragment\r\n",
			URL: &url.URL{
				Scheme:   "http",
				Host:     "example.org",
				Path:     "/path/",
				RawQuery: "query",
				Fragment: "fragment",
			},
		},
		{
			Raw: "\r\n",
			URL: &url.URL{},
		},
		{
			Raw: "gemini://example.com\n",
			Err: io.EOF,
		},
		{
			Raw: "gemini://example.com",
			Err: io.EOF,
		},
		{
			// 1030 bytes
			Raw: maxURL + "xxxxxx",
			Err: io.EOF,
		},
		{
			// 1027 bytes
			Raw: maxURL + "x" + "\r\n",
			Err: io.EOF,
		},
		{
			// 1024 bytes
			Raw: maxURL[:len(maxURL)-2] + "\r\n",
			URL: &url.URL{
				Scheme: "gemini",
				Host:   "example.net",
				Path:   maxURL[len("gemini://example.net") : len(maxURL)-2],
			},
		},
	}

	for _, test := range tests {
		t.Logf("%#v", test.Raw)
		req, err := ReadRequest(strings.NewReader(test.Raw))
		if err != test.Err {
			t.Errorf("expected err = %v, got %v", test.Err, err)
		}
		if req == nil && test.URL != nil {
			t.Errorf("expected url = %s, got nil", test.URL)
		} else if req != nil && test.URL == nil {
			t.Errorf("expected req = nil, got %v", req)
		} else if req != nil && *req.URL != *test.URL {
			t.Errorf("expected url = %v, got %v", *test.URL, *req.URL)
		}
	}
}

func newRequest(rawurl string) *Request {
	req, err := NewRequest(rawurl)
	if err != nil {
		panic(err)
	}
	return req
}

func TestWriteRequest(t *testing.T) {
	tests := []struct {
		Req *Request
		Raw string
		Err error
	}{
		{
			Req: newRequest("gemini://example.com"),
			Raw: "gemini://example.com\r\n",
		},
		{
			Req: newRequest("gemini://example.com/path/?query#fragment"),
			Raw: "gemini://example.com/path/?query#fragment\r\n",
		},
		{
			Req: newRequest(maxURL),
			Raw: maxURL + "\r\n",
		},
		{
			Req: newRequest(maxURL + "x"),
			Err: ErrInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Logf("%s", test.Req.URL)
		var b strings.Builder
		bw := bufio.NewWriter(&b)
		err := test.Req.Write(bw)
		if err != test.Err {
			t.Errorf("expected err = %v, got %v", test.Err, err)
		}
		bw.Flush()
		got := b.String()
		if got != test.Raw {
			t.Errorf("expected %#v, got %#v", test.Raw, got)
		}
	}
}
