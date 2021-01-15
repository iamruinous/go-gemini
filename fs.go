package gemini

import (
	"fmt"
	"io"
	"mime"
	"os"
	"path"
)

func init() {
	// Add Gemini mime types
	if err := mime.AddExtensionType(".gmi", "text/gemini"); err != nil {
		panic(fmt.Errorf("failed to register .gmi extension mimetype: %w", err))
	}

	if err := mime.AddExtensionType(".gemini", "text/gemini"); err != nil {
		panic(fmt.Errorf("failed to register .gemini extension mimetype: %w", err))
	}
}

// FileServer takes a filesystem and returns a Responder which uses that filesystem.
// The returned Responder sanitizes paths before handling them.
//
// TODO: Use io/fs.FS when available.
func FileServer(fsys FS) Responder {
	return fsHandler{fsys}
}

type fsHandler struct {
	FS
}

func (fsh fsHandler) Respond(w *ResponseWriter, r *Request) {
	p := path.Clean(r.URL.Path)
	f, err := fsh.Open(p)
	if err != nil {
		w.Status(StatusNotFound)
		return
	}
	// Detect mimetype
	ext := path.Ext(p)
	mimetype := mime.TypeByExtension(ext)
	w.Meta(mimetype)
	// Copy file to response writer
	_, _ = io.Copy(w, f)
}

// FS represents a filesystem.
//
// TODO: Replace with io/fs.FS when available
type FS interface {
	Open(name string) (File, error)
}

// File represents a file.
//
// TODO: Replace with io/fs.File when available.
type File interface {
	Stat() (os.FileInfo, error)
	Read([]byte) (int, error)
	Close() error
}

// Dir implements FS using the native filesystem restricted to a specific directory.
//
// TODO: replace with os.DirFS when available.
type Dir string

// Open tries to open the file with the given name.
// If the file is a directory, it tries to open the index file in that directory.
func (d Dir) Open(name string) (File, error) {
	p := path.Join(string(d), name)
	return openFile(p)
}

// ServeFile responds to the request with the contents of the named file
// or directory.
//
// TODO: Use io/fs.FS when available.
func ServeFile(w *ResponseWriter, fs FS, name string) {
	f, err := fs.Open(name)
	if err != nil {
		w.Status(StatusNotFound)
		return
	}
	// Detect mimetype
	ext := path.Ext(name)
	mimetype := mime.TypeByExtension(ext)
	w.Meta(mimetype)
	// Copy file to response writer
	_, _ = io.Copy(w, f)
}

func openFile(p string) (File, error) {
	f, err := os.OpenFile(p, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	if stat, err := f.Stat(); err == nil {
		if stat.IsDir() {
			f, err := os.Open(path.Join(p, "index.gmi"))
			if err != nil {
				return nil, err
			}
			stat, err := f.Stat()
			if err != nil {
				return nil, err
			}
			if stat.Mode().IsRegular() {
				return f, nil
			}
			return nil, os.ErrNotExist
		} else if !stat.Mode().IsRegular() {
			return nil, os.ErrNotExist
		}
	}
	return f, nil
}
