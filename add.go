package pin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/pin/manifest"
)

type AddOptions struct {
	Dir         string
	Manifest    string
	Lock        string
	RegistryURL string
	Exact       bool
	DryRun      bool
}

type AddResult struct {
	Entry      manifest.Entry
	Resolved   string
	SyncResult *SyncResult
}

// Add is a one-shot shim around Client.Add.
func Add(ctx context.Context, spec string, files []string, opts AddOptions) (*AddResult, error) {
	return New(ClientOptions{RegistryURL: opts.RegistryURL}).Add(ctx, spec, files, opts)
}

// Add resolves a package's latest-satisfying version, inserts it into
// the manifest at its alphabetic position, and runs Sync.
func (c *Client) Add(ctx context.Context, spec string, files []string, opts AddOptions) (*AddResult, error) {
	if opts.Manifest == "" {
		opts.Manifest = DefaultManifest
	}
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}

	name, constraint := parseSpec(spec)
	if name == "" {
		return nil, fmt.Errorf("add: package name is required")
	}

	src := c.NPM

	resolved, err := src.ResolveVersion(ctx, name, defaultIfEmpty(constraint, "latest"), 0)
	if err != nil {
		return nil, err
	}

	written := constraint
	if written == "" {
		if opts.Exact {
			written = resolved
		} else {
			written = caretMajorMinor(resolved)
		}
	}

	entry := manifest.Entry{Name: name, Version: written, Files: files}

	manifestPath := filepath.Join(opts.Dir, opts.Manifest)
	in, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := manifest.AddEntry(bytes.NewReader(in), &out, entry); err != nil {
		return nil, err
	}

	if opts.DryRun {
		return &AddResult{Entry: entry, Resolved: resolved}, nil
	}
	if err := os.WriteFile(manifestPath, out.Bytes(), filePerm); err != nil {
		return nil, err
	}

	syncRes, err := c.Sync(ctx, SyncOptions{
		Dir:      opts.Dir,
		Manifest: opts.Manifest,
		Lock:     opts.Lock,
	})
	if err != nil {
		return nil, err
	}
	return &AddResult{Entry: entry, Resolved: resolved, SyncResult: syncRes}, nil
}

func parseSpec(spec string) (name, constraint string) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec, ""
	}
	return spec[:at], spec[at+1:]
}

func caretMajorMinor(version string) string {
	parts := strings.SplitN(version, ".", 3) //nolint:mnd
	if len(parts) < 2 {                      //nolint:mnd
		return "^" + version
	}
	return "^" + parts[0] + "." + parts[1]
}

func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
