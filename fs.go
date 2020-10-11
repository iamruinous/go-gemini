package gmi

import (
	"errors"
	"io"
	"os"
	"path"
)

// FileServer errors.
var (
	ErrNotAFile = errors.New("gemini: not a file")
)

// FileServer takes a filesystem and returns a Handler which uses that filesystem.
// The returned Handler sanitizes paths before handling them.
func FileServer(fsys FS) Handler {
	return fsHandler{fsys}
}

type fsHandler struct {
	FS
}

func (fsh fsHandler) Serve(rw *ResponseWriter, req *Request) {
	path := path.Clean(req.URL.Path)
	f, err := fsh.Open(path)
	if err != nil {
		NotFound(rw, req)
		return
	}
	// TODO: detect mimetype
	rw.SetMimetype("text/gemini")
	// Copy file to response writer
	io.Copy(rw, f)
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
