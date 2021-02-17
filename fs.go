package gemini

import (
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/url"
	"path"
	"sort"
	"strings"
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
	ServeFile(w, fs, path.Clean(r.URL.Path))
}

// ServeFile responds to the request with the contents of the named file
// or directory.
//
// If the provided file or directory name is a relative path, it is interpreted
// relative to the current directory and may ascend to parent directories. If
// the provided name is constructed from user input, it should be sanitized
// before calling ServeFile.
func ServeFile(w ResponseWriter, fsys fs.FS, name string) {
	if name == "/" {
		name = "."
	} else {
		name = strings.TrimPrefix(name, "/")
	}

	f, err := fsys.Open(name)
	if err != nil {
		w.Status(StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		w.Status(StatusTemporaryFailure)
		return
	}

	if stat.IsDir() {
		// Try opening index file
		index, err := fsys.Open(path.Join(name, "index.gmi"))
		if err == nil {
			defer index.Close()
			istat, err := index.Stat()
			if err == nil {
				f = index
				stat = istat
			}
		}
	}

	if stat.IsDir() {
		// Failed to find index file
		dirList(w, f)
		return
	}

	// Detect mimetype from file extension
	ext := path.Ext(name)
	mimetype := mime.TypeByExtension(ext)
	w.Meta(mimetype)
	io.Copy(w, f)
}

func dirList(w ResponseWriter, f fs.File) {
	var entries []fs.DirEntry
	var err error
	d, ok := f.(fs.ReadDirFile)
	if ok {
		entries, err = d.ReadDir(-1)
	}
	if !ok || err != nil {
		w.Header(StatusTemporaryFailure, "Error reading directory")
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		link := LineLink{
			Name: name,
			URL:  (&url.URL{Path: name}).EscapedPath(),
		}
		fmt.Fprintln(w, link.String())
	}
}
