// Package pinfs is the writable-filesystem abstraction for pin's
// outputs: vendored asset files and the pin.lock. OS is the default;
// alternative Writers pipe outputs into memory, an archive, or any
// other target without changing pin's resolve and sync logic.
//
// Writer paths are slash-separated. The OS implementation joins them
// with its constructor-provided root.
package pinfs

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	dirPerm  = 0o755
	filePerm = 0o644
)

// Writer is the minimal interface pin uses to emit its outputs.
// Implementations must make WriteFile atomic, create parent
// directories on write, and tolerate not-exist errors on Remove.
type Writer interface {
	WriteFile(path string, data []byte) error

	// ReadFile returns fs.ErrNotExist-wrapped for missing paths. Pin
	// uses it to skip rewriting an unchanged lockfile; an
	// implementation that doesn't support reads can return
	// fs.ErrNotExist unconditionally.
	ReadFile(path string) ([]byte, error)

	Remove(path string) error
}

// OS returns a Writer rooted at root. WriteFile uses tmp+rename;
// Remove prunes empty parent directories upward until reaching root.
//
//nolint:ireturn // the writer plug-in surface is interface-typed by design
func OS(root string) Writer {
	return &osWriter{root: filepath.Clean(root)}
}

type osWriter struct {
	root string
}

func (w *osWriter) abs(p string) string {
	return filepath.Join(w.root, filepath.FromSlash(p))
}

func (w *osWriter) WriteFile(path string, data []byte) error {
	dst := w.abs(path)
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}
	if existing, err := os.ReadFile(dst); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, filePerm); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (w *osWriter) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(w.abs(path))
}

func (w *osWriter) Remove(path string) error {
	dst := w.abs(path)
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	w.pruneEmpty(filepath.Dir(dst))
	return nil
}

func (w *osWriter) pruneEmpty(dir string) {
	for dir != w.root && dir != "." && dir != string(filepath.Separator) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := os.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}
