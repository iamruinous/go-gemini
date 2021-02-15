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

// A FileSystem implements access to a collection of named files. The elements
// in a file path are separated by slash ('/', U+002F) characters, regardless
// of host operating system convention.
type FileSystem interface {
	Open(name string) (File, error)
}

// A File is returned by a FileSystem's Open method and can be served by the
// FileServer implementation.
//
// The methods should behave the same as those on an *os.File.
type File interface {
	Stat() (os.FileInfo, error)
	Read([]byte) (int, error)
	Close() error
}

// A Dir implements FileSystem using the native file system restricted
// to a specific directory tree.
//
// While the FileSystem.Open method takes '/'-separated paths, a Dir's string
// value is a filename on the native file system, not a URL, so it is separated
// by filepath.Separator, which isn't necessarily '/'.
//
// Note that Dir could expose sensitive files and directories. Dir will follow
// symlinks pointing out of the directory tree, which can be especially
// dangerous if serving from a directory in which users are able to create
// arbitrary symlinks. Dir will also allow access to files and directories
// starting with a period, which could expose sensitive directories like .git
// or sensitive files like .htpasswd. To exclude files with a leading period,
// remove the files/directories from the server or create a custom FileSystem
// implementation.
//
// An empty Dir is treated as ".".
type Dir string

// Open implements FileSystem using os.Open, opening files for reading
// rooted and relative to the directory d.
func (d Dir) Open(name string) (File, error) {
	return os.Open(path.Join(string(d), name))
}

// FileServer returns a handler that serves Gemini requests with the contents
// of the provided file system.
//
// To use the operating system's file system implementation, use gemini.Dir:
//
//     gemini.FileServer(gemini.Dir("/tmp"))
func FileServer(fsys FileSystem) Handler {
	return fileServer{fsys}
}

type fileServer struct {
	FileSystem
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
func ServeFile(w ResponseWriter, fsys FileSystem, name string) {
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

func openFile(fsys FileSystem, name string) (File, error) {
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

	return nil, os.ErrNotExist
}
