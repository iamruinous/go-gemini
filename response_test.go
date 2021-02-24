package gemini

import (
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

func TestReadWriteResponse(t *testing.T) {
	tests := []struct {
		Raw       string
		Status    Status
		Meta      string
		Body      string
		Err       error
		SkipWrite bool
	}{
		{
			Raw:    "20 text/gemini\r\nHello, world!\nWelcome to my capsule.",
			Status: 20,
			Meta:   "text/gemini",
			Body:   "Hello, world!\nWelcome to my capsule.",
		},
		{
			Raw:    "10 Search query\r\n",
			Status: 10,
			Meta:   "Search query",
		},
		{
			Raw:    "30 /redirect\r\n",
			Status: 30,
			Meta:   "/redirect",
		},
		{
			Raw:       "31 /redirect\r\nThis body is ignored.",
			Status:    31,
			Meta:      "/redirect",
			SkipWrite: true, // skip write test since result won't match Raw
		},
		{
			Raw:    "99 Unknown status code\r\n",
			Status: 99,
			Meta:   "Unknown status code",
		},
		{
			Raw: "\r\n",
			Err: ErrInvalidResponse,
		},
		{
			Raw: "\n",
			Err: ErrInvalidResponse,
		},
		{
			Raw: "1 Bad response\r\n",
			Err: ErrInvalidResponse,
		},
		{
			Raw: "",
			Err: io.EOF,
		},
		{
			Raw: "10 Search query",
			Err: io.EOF,
		},
		{
			Raw: "20 text/gemini\nHello, world!",
			Err: io.EOF,
		},
		{
			Raw: "20 text/gemini\rHello, world!",
			Err: ErrInvalidResponse,
		},
		{
			Raw: "20 text/gemini\r",
			Err: io.EOF,
		},
		{
			Raw: "abcdefghijklmnopqrstuvwxyz",
			Err: ErrInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Logf("%#v", test.Raw)
		resp, err := ReadResponse(ioutil.NopCloser(strings.NewReader(test.Raw)))
		if err != test.Err {
			t.Errorf("expected err = %v, got %v", test.Err, err)
		}
		if test.Err != nil {
			// No response
			continue
		}
		if resp.status != test.Status {
			t.Errorf("expected status = %d, got %d", test.Status, resp.status)
		}
		if resp.meta != test.Meta {
			t.Errorf("expected meta = %s, got %s", test.Meta, resp.meta)
		}
		b, _ := ioutil.ReadAll(resp.body)
		body := string(b)
		if body != test.Body {
			t.Errorf("expected body = %#v, got %#v", test.Body, body)
		}
	}

	for _, test := range tests {
		if test.Err != nil || test.SkipWrite {
			continue
		}

		var b strings.Builder
		w := newResponseWriter(nopCloser{&b})
		w.WriteHeader(test.Status, test.Meta)
		io.Copy(w, strings.NewReader(test.Body))
		if err := w.Flush(); err != nil {
			t.Error(err)
			continue
		}

		got := b.String()
		if got != test.Raw {
			t.Errorf("expected %#v, got %#v", test.Raw, got)
		}
	}
}
