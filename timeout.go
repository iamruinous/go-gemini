package gemini

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// TimeoutHandler returns a Handler that runs h with the given time limit.
//
// The new Handler calls h.ServeGemini to handle each request, but
// if a call runs for longer than its time limit, the handler responds with a
// 40 Temporary Failure error. After such a timeout, writes by h to its
// ResponseWriter will return ErrHandlerTimeout.
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

	done := make(chan struct{})
	tw := &timeoutWriter{}
	panicChan := make(chan interface{}, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				panicChan <- p
			}
		}()
		t.h.ServeGemini(ctx, tw, r)
		close(done)
	}()

	select {
	case p := <-panicChan:
		panic(p)
	case <-done:
		tw.mu.Lock()
		defer tw.mu.Unlock()
		if !tw.wroteHeader {
			tw.status = StatusSuccess
		}
		w.WriteHeader(tw.status, tw.meta)
		w.Write(tw.b.Bytes())
	case <-ctx.Done():
		tw.mu.Lock()
		defer tw.mu.Unlock()
		w.WriteHeader(StatusTemporaryFailure, "Timeout")
		tw.timedOut = true
	}
}

type timeoutWriter struct {
	mu          sync.Mutex
	b           bytes.Buffer
	status      Status
	meta        string
	mediatype   string
	wroteHeader bool
	timedOut    bool
}

func (w *timeoutWriter) SetMediaType(mediatype string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mediatype = mediatype
}

func (w *timeoutWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return 0, ErrHandlerTimeout
	}
	if !w.wroteHeader {
		w.writeHeaderLocked(StatusSuccess, w.mediatype)
	}
	return w.b.Write(b)
}

func (w *timeoutWriter) WriteHeader(status Status, meta string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timedOut {
		return
	}
	w.writeHeaderLocked(status, meta)
}

func (w *timeoutWriter) writeHeaderLocked(status Status, meta string) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.meta = meta
	w.wroteHeader = true
}

func (w *timeoutWriter) Flush() error {
	return nil
}
