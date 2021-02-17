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
	serveFile(w, r, fs, path.Clean(r.URL.Path), true)
}

// ServeContent replies to the request using the content in the
// provided Reader. The main benefit of ServeContent over io.Copy
// is that it sets the MIME type of the response.
//
// ServeContent tries to deduce the type from name's file extension.
// The name is otherwise unused; it is never sent in the response.
func ServeContent(w ResponseWriter, r *Request, name string, content io.Reader) {
	serveContent(w, name, content)
}

func serveContent(w ResponseWriter, name string, content io.Reader) {
	// Detect mimetype from file extension
	ext := path.Ext(name)
	mimetype := mime.TypeByExtension(ext)
	w.Meta(mimetype)
	io.Copy(w, content)
}

// ServeFile responds to the request with the contents of the named file
// or directory.
//
// If the provided file or directory name is a relative path, it is interpreted
// relative to the current directory and may ascend to parent directories. If
// the provided name is constructed from user input, it should be sanitized
// before calling ServeFile.
func ServeFile(w ResponseWriter, r *Request, fsys fs.FS, name string) {
	serveFile(w, r, fsys, name, false)
}

func serveFile(w ResponseWriter, r *Request, fsys fs.FS, name string, redirect bool) {
	const indexPage = "/index.gmi"

	// Redirect .../index.gmi to .../
	if strings.HasSuffix(r.URL.Path, indexPage) {
		w.Header(StatusPermanentRedirect, "./")
		return
	}

	if name == "/" {
		name = "."
	} else {
		name = strings.Trim(name, "/")
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

	// Redirect to canonical path
	if redirect {
		url := r.URL.Path
		if stat.IsDir() {
			// Add trailing slash
			if url[len(url)-1] != '/' {
				w.Header(StatusPermanentRedirect, path.Base(url)+"/")
				return
			}
		} else {
			// Remove trailing slash
			if url[len(url)-1] == '/' {
				w.Header(StatusPermanentRedirect, "../"+path.Base(url))
				return
			}
		}
	}

	if stat.IsDir() {
		// Redirect if the directory name doesn't end in a slash
		url := r.URL.Path
		if url[len(url)-1] != '/' {
			w.Header(StatusRedirect, path.Base(url)+"/")
			return
		}

		// Use contents of index.gmi if present
		index, err := fsys.Open(path.Join(name, indexPage))
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

	serveContent(w, name, f)
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
