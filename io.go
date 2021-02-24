package gemini

import (
	"bufio"
	"context"
	"io"
)

type contextReader struct {
	ctx    context.Context
	done   <-chan struct{}
	cancel func()
	rc     io.ReadCloser
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.done:
		r.rc.Close()
		return 0, r.ctx.Err()
	default:
	}
	n, err := r.rc.Read(p)
	if err != nil {
		r.cancel()
	}
	return n, err
}

func (r *contextReader) Close() error {
	r.cancel()
	return r.rc.Close()
}

type contextWriter struct {
	ctx    context.Context
	done   <-chan struct{}
	cancel func()
	wc     io.WriteCloser
}

func (w *contextWriter) Write(b []byte) (int, error) {
	select {
	case <-w.done:
		w.wc.Close()
		return 0, w.ctx.Err()
	default:
	}
	n, err := w.wc.Write(b)
	if err != nil {
		w.cancel()
	}
	return n, err
}

func (w *contextWriter) Close() error {
	w.cancel()
	return w.wc.Close()
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error {
	return nil
}

type nopReadCloser struct{}

func (nopReadCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (nopReadCloser) Close() error {
	return nil
}

type bufReadCloser struct {
	br *bufio.Reader // used until empty
	io.ReadCloser
}

func newBufReadCloser(br *bufio.Reader, rc io.ReadCloser) io.ReadCloser {
	body := &bufReadCloser{ReadCloser: rc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

func (b *bufReadCloser) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadCloser.Read(p)
}
