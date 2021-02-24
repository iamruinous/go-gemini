package gemini

import (
	"bytes"
	"context"
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

func (t *timeoutHandler) ServeGemini(ctx context.Context, w *ResponseWriter, r *Request) {
	ctx, cancel := context.WithTimeout(ctx, t.dt)
	defer cancel()

	conn := w.Hijack()

	var b bytes.Buffer
	w.reset(nopCloser{&b})

	done := make(chan struct{})
	go func() {
		t.h.ServeGemini(ctx, w, r)
		close(done)
	}()

	select {
	case <-done:
		conn.Write(b.Bytes())
	case <-ctx.Done():
		w.reset(conn)
		w.WriteHeader(StatusTemporaryFailure, "Timeout")
	}
}
