// Package source defines the common Resolver interface that every source
// kind (npm, github, gitlab, ...) implements. Identity is purl-driven: a
// resolver takes a *purl.PURL and the requested file paths, fetches the
// bytes, anchors integrity, and returns the resolved metadata.
//
// Adding a new source kind is one new sub-package implementing Resolver
// plus one line in sync.go's dispatch map.
package source

import (
	"context"

	"github.com/git-pkgs/purl"
)

// Resolver fetches a package's files and returns the bytes plus identity
// metadata. Implementations live in source/npm, source/forge, etc.
type Resolver interface {
	// Resolve returns the fetched files and identity for the package
	// identified by p, restricted to the named files (or the package's
	// declared entry point if files is empty, for sources that support it).
	Resolve(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error)
}

// Resolved is the unified output of a Resolver. PackageIntegrity holds
// whatever the source treats as its tarball-level anchor: an SRI string
// for npm (sha512-<base64> of the tarball), a commit SHA for forge sources
// (SHA-1 hex of the resolved commit), or a TOFU SRI for url sources.
type Resolved struct {
	PURL             string
	Name             string
	Version          string
	PackageIntegrity string
	License          string
	SourceRepository string
	Files            []ResolvedFile
}

// ResolvedFile is one fetched file inside a package.
type ResolvedFile struct {
	Path      string
	Integrity string
	Size      int64
	URL       string
	Content   []byte
}
