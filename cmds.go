package pin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/git-pkgs/pin/manifest"
)

const initTemplate = `out: "static/vendor"

assets: []
`

func Init(dir, manifestPath string) error {
	if manifestPath == "" {
		manifestPath = DefaultManifest
	}
	p := filepath.Join(dir, manifestPath)
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%s already exists", p)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.WriteFile(p, []byte(initTemplate), filePerm)
}

// Remove is a one-shot shim around Client.Remove.
func Remove(ctx context.Context, names []string, opts SyncOptions) (*SyncResult, error) {
	c, err := clientFromSyncOptions(opts)
	if err != nil {
		return nil, err
	}
	return c.Remove(ctx, names, opts)
}

// Remove deletes the named entries from the manifest and runs Sync to
// clean up the resulting lockfile and on-disk files.
func (c *Client) Remove(ctx context.Context, names []string, opts SyncOptions) (*SyncResult, error) {
	if opts.Manifest == "" {
		opts.Manifest = DefaultManifest
	}
	manifestPath := filepath.Join(opts.Dir, opts.Manifest)
	in, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	current := in
	for _, name := range names {
		var out bytes.Buffer
		if err := manifest.RemoveEntry(bytes.NewReader(current), &out, name); err != nil {
			return nil, err
		}
		current = out.Bytes()
	}
	if opts.DryRun {
		return &SyncResult{}, nil
	}
	if err := os.WriteFile(manifestPath, current, filePerm); err != nil {
		return nil, err
	}
	return c.Sync(ctx, opts)
}

type ListEntry struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	Path      string `json:"path"`
	Out       string `json:"out"`
	Type      string `json:"type"`
	Integrity string `json:"integrity"`
	Size      int64  `json:"size"`
}

func List(opts VerifyOptions) ([]ListEntry, error) {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}
	l, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("no lockfile at %s; run sync first", filepath.Join(opts.Dir, opts.Lock))
	}
	out := make([]ListEntry, 0, len(l.Assets))
	for _, a := range l.Assets {
		out = append(out, ListEntry{
			Name:      a.Name,
			Version:   a.Version,
			PURL:      a.PURL,
			Path:      a.Path,
			Out:       a.Out,
			Type:      a.Type,
			Integrity: a.Integrity,
			Size:      a.Size,
		})
	}
	return out, nil
}

func Path(name string, opts VerifyOptions) ([]string, error) {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}
	l, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("no lockfile at %s; run sync first", filepath.Join(opts.Dir, opts.Lock))
	}
	var paths []string
	for _, a := range l.Assets {
		if a.Name == name {
			paths = append(paths, filepath.Join(opts.Dir, l.OutDir, filepath.FromSlash(a.Out)))
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s not found in lockfile", name)
	}
	return paths, nil
}
