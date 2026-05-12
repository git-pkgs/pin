// Package source defines the common Resolver interface every source
// kind (npm, github, gitlab, ipfs, internal artifact registries, ...)
// implements. Identity is purl-driven: a resolver takes a *purl.PURL
// and the requested file paths, fetches the bytes, anchors integrity,
// and returns the resolved metadata.
//
// Adding a new source kind to a pin Client:
//
//  1. Implement source.Resolver. The single Resolve method receives a
//     purl and the file list the manifest requested.
//
//  2. Register the resolver against the purl type at Client setup:
//
//     c := pin.New(pin.ClientOptions{})
//     c.RegisterResolver("ipfs", myIPFSResolver)
//
//     Manifest entries whose purl type matches dispatch to that
//     resolver. Built-in resolvers (npm, github, generic) are
//     registered by pin.New and can be replaced by re-registering the
//     same purl type.
//
// Plug-in resolvers populate whichever Resolved/ResolvedFile fields
// they have available and leave the rest zero. The pin core treats
// missing optional fields (License, Attestation, SourceRepository,
// URL on a file, etc.) as "unknown" rather than errors.
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

// Resolved is the unified output of a Resolver.
//
// Required fields a plug-in resolver MUST populate:
//
//	PURL    — the canonical purl of the resolved package, version-pinned
//	Name    — display name (may equal the purl's Name)
//	Version — the resolved exact version string
//	Files   — the fetched files; at least one entry, each with Path,
//	          Integrity, Size, and Content populated
//
// Optional fields a plug-in resolver MAY populate:
//
//	PackageIntegrity — source-specific package-level anchor (npm: sha512
//	          SRI of the tarball; forge: commit SHA; url: SHA-384 SRI)
//	License          — SPDX or registry-supplied license string
//	SourceRepository — the package's declared repository URL
//	Attestation      — SLSA Provenance v1 fields when the version was
//	          built with trusted publishing
type Resolved struct {
	PURL             string
	Name             string
	Version          string
	PackageIntegrity string
	License          string
	SourceRepository string
	Attestation      *Attestation
	Files            []ResolvedFile
}

// Attestation holds the publisher-side provenance metadata for a package
// version. Fields follow SLSA Provenance v1 vocabulary. Nil when the
// version was published without provenance.
type Attestation struct {
	PredicateType    string
	BuilderID        string
	SourceRepository string
	SourceRevision   string
	SignerIdentity   string
	BundleURL        string
}

// ResolvedFile is one fetched file inside a package.
type ResolvedFile struct {
	Path      string
	Integrity string
	Size      int64
	URL       string
	Content   []byte
}

// ProvenanceVerifier validates a provenance attestation's cryptographic
// envelope against the claimed artifact bytes. The bundle body is the
// raw JSON of the attestation envelope (DSSE/in-toto/sigstore-shape);
// digestAlg is "sha256" or "sha512"; digest is the raw bytes of that
// hash over the artifact the attestation's subject points at.
//
// Implementations:
//
//   - source/sigstore — sigstore-go via Sigstore's TUF trust
//     root. The default; handles both npm tarball (sha512) and GitHub
//     artifact (sha256) attestations.
//
// Future implementations (witness, SBOMit, plain in-toto) plug in here
// without changing source/npm or source/forge.
type ProvenanceVerifier interface {
	VerifyBundle(ctx context.Context, bundleBody []byte, digestAlg string, digest []byte) error
}
