package gemini

import (
	"io"
	"io/fs"
	"mime"
	"path"
)

func init() {
	// Add Gemini mime types
	mime.AddExtensionType(".gmi", "text/gemini")
	mime.AddExtensionType(".gemini", "text/gemini")
}

// FileServer returns a handler that serves Gemini requests with the contents
// of the provided file system.
//
// To use the operating system's file system implementation, use os.DirFS:
//
//     gemini.FileServer(os.DirFS("/tmp"))
func FileServer(fsys fs.FS) Handler {
	return fileServer{fsys}
}

type fileServer struct {
	fs.FS
}

func (fs fileServer) ServeGemini(w ResponseWriter, r *Request) {
	ServeFile(w, fs, r.URL.Path)
}

// ServeFile responds to the request with the contents of the named file
// or directory.
//
// If the provided file or directory name is a relative path, it is interpreted
// relative to the current directory and may ascend to parent directories. If
// the provided name is constructed from user input, it should be sanitized
// before calling ServeFile.
func ServeFile(w ResponseWriter, fsys fs.FS, name string) {
	f, err := openFile(fsys, name)
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

func openFile(fsys fs.FS, name string) (fs.File, error) {
	f, err := fsys.Open(name)
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

	if stat.IsDir() {
		// Try opening index.gmi
		f, err := fsys.Open(path.Join(name, "index.gmi"))
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
	}

	return nil, fs.ErrNotExist
}
