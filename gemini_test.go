package gmi

import (
	"math/rand"
	"testing"
	"time"
)

func TestServeMuxEntryOrder(t *testing.T) {
	expected := []string{
		"https://example.com/longpath",
		"https://example.com/path",
		"https://example.com",
		"http://example.com/longpath",
		"http://example.com/path",
		"http://example.com",
		"example.com/longpath",
		"example.com/path",
		"example.com",
		"/longpath",
		"/path",
		"/",
	}

	// Shuffle input
	a := make([]string, len(expected))
	copy(expected, a)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })

	mux := &ServeMux{}
	for _, s := range a {
		mux.Handle(s, nil)
	}
	for i, e := range mux.es {
		s := e.u.String()
		if s != expected[i] {
			t.Errorf("wrong order of mux entries: expected %s, got %s", expected[i], s)
		}
	}
}
