package gemini

import (
	"io"
	"mime"
	"os"
	"path"
)

func init() {
	// Add Gemini mime types
	mime.AddExtensionType(".gmi", "text/gemini")
	mime.AddExtensionType(".gemini", "text/gemini")
}

// FileServer takes a filesystem and returns a Responder which uses that filesystem.
// The returned Responder sanitizes paths before handling them.
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
		w.WriteStatus(StatusNotFound)
		return
	}
	// Detect mimetype
	ext := path.Ext(p)
	mimetype := mime.TypeByExtension(ext)
	w.SetMimetype(mimetype)
	// Copy file to response writer
	io.Copy(w, f)
}

// TODO: replace with io/fs.FS when available
type FS interface {
	Open(name string) (File, error)
}

// TODO: replace with io/fs.File when available
type File interface {
	Stat() (os.FileInfo, error)
	Read([]byte) (int, error)
	Close() error
}

// Dir implements FS using the native filesystem restricted to a specific directory.
type Dir string

// Open tries to open the file with the given name.
// If the file is a directory, it tries to open the index file in that directory.
func (d Dir) Open(name string) (File, error) {
	p := path.Join(string(d), name)
	return openFile(p)
}

// ServeFile responds to the request with the contents of the named file
// or directory.
// TODO: Use io/fs.FS when available.
func ServeFile(w *ResponseWriter, fs FS, name string) {
	f, err := fs.Open(name)
	if err != nil {
		w.WriteStatus(StatusNotFound)
		return
	}
	// Detect mimetype
	ext := path.Ext(name)
	mimetype := mime.TypeByExtension(ext)
	w.SetMimetype(mimetype)
	// Copy file to response writer
	io.Copy(w, f)
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
			return nil, ErrNotAFile
		} else if !stat.Mode().IsRegular() {
			return nil, ErrNotAFile
		}
	}
	return f, nil
}
