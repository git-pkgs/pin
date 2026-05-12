package pinfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestOS_WriteAndReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)

	if err := w.WriteFile("a/b/c.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := w.ReadFile("a/b/c.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("ReadFile = %q, want hello", got)
	}
}

func TestOS_WriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)
	if err := w.WriteFile("file.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile("file.txt", []byte("second")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "second" {
		t.Errorf("got %q, want second", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("tmp file left behind: %s", e.Name())
		}
	}
}

func TestOS_WriteSkipsIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)
	if err := w.WriteFile("a.txt", []byte("same")); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile("a.txt", []byte("same")); err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Errorf("identical-content WriteFile should noop, but mtime changed")
	}
}

func TestOS_ReadFileMissingReturnsNotExist(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)
	_, err := w.ReadFile("nope")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestOS_RemoveIgnoresMissing(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)
	if err := w.Remove("does-not-exist"); err != nil {
		t.Errorf("Remove of missing path: %v", err)
	}
}

func TestOS_RemovePrunesEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	w := OS(dir)
	if err := w.WriteFile("a/b/c.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove("a/b/c.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected pruned a/, got err = %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("root dir should remain: %v", err)
	}
}

func TestMemory_RoundTrip(t *testing.T) {
	m := NewMemory()
	if err := m.WriteFile("vendor/a.js", []byte("x")); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadFile("vendor/a.js")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "x" {
		t.Errorf("got %q, want x", got)
	}
	b, ok := m.Get("vendor/a.js")
	if !ok || string(b) != "x" {
		t.Errorf("Get = %q, %v; want x, true", b, ok)
	}
	if len(m.Files()) != 1 {
		t.Errorf("Files len = %d, want 1", len(m.Files()))
	}
}

func TestMemory_ReadMissingReturnsNotExist(t *testing.T) {
	m := NewMemory()
	_, err := m.ReadFile("nope")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestMemory_RemoveIgnoresMissing(t *testing.T) {
	m := NewMemory()
	if err := m.Remove("does-not-exist"); err != nil {
		t.Error(err)
	}
}

func TestMemory_FilesIsSnapshot(t *testing.T) {
	m := NewMemory()
	_ = m.WriteFile("a", []byte("v1"))
	snap := m.Files()
	_ = m.WriteFile("a", []byte("v2"))
	if string(snap["a"]) != "v1" {
		t.Errorf("snapshot mutated: %q", snap["a"])
	}
}
