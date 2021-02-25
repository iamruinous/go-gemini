// +build ignore

// This example illustrates a Gemini server.

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"time"

	"git.sr.ht/~adnano/go-gemini"
	"git.sr.ht/~adnano/go-gemini/certificate"
)

func main() {
	certificates := &certificate.Store{}
	certificates.Register("localhost")
	if err := certificates.Load("/var/lib/gemini/certs"); err != nil {
		log.Fatal(err)
	}

	mux := &gemini.ServeMux{}
	mux.Handle("/", gemini.FileServer(os.DirFS("/var/www")))

	server := &gemini.Server{
		Handler:        logMiddleware(mux),
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   1 * time.Minute,
		GetCertificate: certificates.Get,
	}

	// Listen for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	errch := make(chan error)
	go func() {
		ctx := context.Background()
		errch <- server.ListenAndServe(ctx)
	}()

	select {
	case err := <-errch:
		log.Fatal(err)
	case <-c:
		// Shutdown the server
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func logMiddleware(h gemini.Handler) gemini.Handler {
	return gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
		lw := &logResponseWriter{rw: w}
		h.ServeGemini(ctx, lw, r)
		host := r.TLS().ServerName
		log.Printf("gemini: %s %q %d %d", host, r.URL, lw.status, lw.wrote)
	})
}

type logResponseWriter struct {
	rw          gemini.ResponseWriter
	status      gemini.Status
	meta        string
	mediatype   string
	wroteHeader bool
	wrote       int
}

func (w *logResponseWriter) SetMediaType(mediatype string) {
	w.mediatype = mediatype
}

func (w *logResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(gemini.StatusSuccess, w.mediatype)
	}
	n, err := w.rw.Write(b)
	w.wrote += n
	return n, err
}

func (w *logResponseWriter) WriteHeader(status gemini.Status, meta string) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.meta = meta
	w.wroteHeader = true
	w.rw.WriteHeader(status, meta)
	w.wrote += len(meta) + 5
}

func (w *logResponseWriter) Flush() error {
	return nil
}
