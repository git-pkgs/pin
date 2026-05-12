package pinfs

import (
	"io/fs"
	"sync"
)

// Memory is an in-memory Writer. The contents map is the source of
// truth; iterate via Files() or look up a single entry via Get(). A
// zero-value *Memory is not usable — construct one via NewMemory.
type Memory struct {
	mu    sync.Mutex
	files map[string][]byte
}

// NewMemory returns an empty in-memory Writer.
func NewMemory() *Memory {
	return &Memory{files: map[string][]byte{}}
}

func (m *Memory) WriteFile(path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.files[path] = cp
	return nil
}

func (m *Memory) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[path]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (m *Memory) Remove(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, path)
	return nil
}

// Files returns a snapshot of the in-memory contents keyed by
// slash-separated path. The returned map is owned by the caller; the
// returned byte slices are copies.
func (m *Memory) Files() map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.files))
	for k, v := range m.files {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// Get returns the bytes stored at path and whether the path exists.
// The returned slice is a copy.
func (m *Memory) Get(path string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[path]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, true
}
