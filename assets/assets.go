// Package assets is the runtime helper a Go web app uses to consume
// pin's output: parse the lockfile, serve the vendored files, and emit
// HTML tags with integrity attributes.
//
// Importing this package pulls in only the lock and integrity packages,
// not the npm fetcher or any HTTP machinery, so it stays lean for
// servers that only need to render templates.
package assets

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"

	"github.com/git-pkgs/pin/lock"
)

type Lock = lock.Lock
type Asset = lock.Asset

// Parse reads a pin.lock CycloneDX BOM into a flat Lock model.
func Parse(r io.Reader) (*Lock, error) {
	return lock.Read(r)
}

// FS returns a sub-filesystem rooted at the lockfile's out directory.
// Pass an embed.FS that includes the vendored tree at outDir.
func FS(fsys fs.FS, l *Lock) (fs.FS, error) {
	if l.OutDir == "" {
		return fsys, nil
	}
	return fs.Sub(fsys, l.OutDir)
}

// Options controls how tags are rendered.
type Options struct {
	// Prefix is prepended to each asset's out path to form the src/href.
	// Typically the route the static file server is mounted under,
	// e.g. "/static/vendor/". A trailing slash is not added.
	Prefix string
}

// Tag returns one HTML tag per file the named package vendored, in
// lockfile order. Use this when load order matters (stylesheets,
// scripts with extension dependencies) so the template chooses
// order explicitly.
func Tag(l *Lock, name string, opts Options) []template.HTML {
	var out []template.HTML
	for _, a := range l.Assets {
		if a.Name == name {
			out = append(out, render(&a, opts))
		}
	}
	return out
}

// Tags returns one HTML tag per file of the given asset type across all
// packages, in lockfile (alphabetic) order. Fine for fonts and images;
// not recommended for stylesheets or scripts where load order matters.
func Tags(l *Lock, assetType string, opts Options) []template.HTML {
	var out []template.HTML
	for _, a := range l.Assets {
		if a.Type == assetType {
			out = append(out, render(&a, opts))
		}
	}
	return out
}

func render(a *Asset, opts Options) template.HTML {
	src := html.EscapeString(opts.Prefix + a.Out)
	sri := html.EscapeString(a.Integrity)
	switch lock.AssetType(a.Type) {
	case lock.TypeScript:
		return template.HTML(fmt.Sprintf( //nolint:gosec
			`<script src="%s" integrity="%s" crossorigin="anonymous"></script>`, src, sri))
	case lock.TypeStyle:
		return template.HTML(fmt.Sprintf( //nolint:gosec
			`<link rel="stylesheet" href="%s" integrity="%s" crossorigin="anonymous">`, src, sri))
	case lock.TypeFont:
		return template.HTML(fmt.Sprintf( //nolint:gosec
			`<link rel="preload" as="font" href="%s" crossorigin="anonymous">`, src))
	default:
		return template.HTML(fmt.Sprintf( //nolint:gosec
			`<link rel="preload" href="%s" integrity="%s" crossorigin="anonymous">`, src, sri))
	}
}

// SRI returns the Subresource Integrity string for the named package's
// first file, suitable for direct use in a <script integrity=""> attribute
// when rendering tags by hand.
func SRI(l *Lock, name string) string {
	for _, a := range l.Assets {
		if a.Name == name {
			return a.Integrity
		}
	}
	return ""
}
