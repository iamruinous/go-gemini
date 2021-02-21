package gemini

import (
	"context"
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

func (fs fileServer) ServeGemini(ctx context.Context, w ResponseWriter, r *Request) {
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
	w.MediaType(mimetype)
	io.Copy(w, content)
}

// ServeFile responds to the request with the contents of the named file
// or directory.
//
// If the provided file or directory name is a relative path, it is interpreted
// relative to the current directory and may ascend to parent directories. If
// the provided name is constructed from user input, it should be sanitized
// before calling ServeFile.
//
// As a precaution, ServeFile will reject requests where r.URL.Path contains a
// ".." path element; this protects against callers who might unsafely use
// filepath.Join on r.URL.Path without sanitizing it and then use that
// filepath.Join result as the name argument.
//
// As another special case, ServeFile redirects any request where r.URL.Path
// ends in "/index.gmi" to the same path, without the final "index.gmi". To
// avoid such redirects either modify the path or use ServeContent.
//
// Outside of those two special cases, ServeFile does not use r.URL.Path for
// selecting the file or directory to serve; only the file or directory
// provided in the name argument is used.
func ServeFile(w ResponseWriter, r *Request, fsys fs.FS, name string) {
	if containsDotDot(r.URL.Path) {
		// Too many programs use r.URL.Path to construct the argument to
		// serveFile. Reject the request under the assumption that happened
		// here and ".." may not be wanted.
		// Note that name might not contain "..", for example if code (still
		// incorrectly) used filepath.Join(myDir, r.URL.Path).
		w.WriteHeader(StatusBadRequest, "invalid URL path")
		return
	}
	serveFile(w, r, fsys, name, false)
}

func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

func serveFile(w ResponseWriter, r *Request, fsys fs.FS, name string, redirect bool) {
	const indexPage = "/index.gmi"

	// Redirect .../index.gmi to .../
	if strings.HasSuffix(r.URL.Path, indexPage) {
		w.WriteHeader(StatusPermanentRedirect, "./")
		return
	}

	if name == "/" {
		name = "."
	} else {
		name = strings.Trim(name, "/")
	}

	f, err := fsys.Open(name)
	if err != nil {
		w.WriteHeader(StatusNotFound, "Not found")
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		w.WriteHeader(StatusTemporaryFailure, "Temporary failure")
		return
	}

	// Redirect to canonical path
	if redirect {
		url := r.URL.Path
		if stat.IsDir() {
			// Add trailing slash
			if url[len(url)-1] != '/' {
				w.WriteHeader(StatusPermanentRedirect, path.Base(url)+"/")
				return
			}
		} else {
			// Remove trailing slash
			if url[len(url)-1] == '/' {
				w.WriteHeader(StatusPermanentRedirect, "../"+path.Base(url))
				return
			}
		}
	}

	if stat.IsDir() {
		// Redirect if the directory name doesn't end in a slash
		url := r.URL.Path
		if url[len(url)-1] != '/' {
			w.WriteHeader(StatusRedirect, path.Base(url)+"/")
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
		w.WriteHeader(StatusTemporaryFailure, "Error reading directory")
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
