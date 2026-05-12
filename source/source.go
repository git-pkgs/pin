// Package source is the plug-in surface for new source kinds.
// Identity is purl-driven: a resolver takes a *purl.PURL and the
// requested files, fetches bytes, anchors integrity, and returns the
// resolved metadata.
//
// Adding a source kind to a pin Client:
//
//  1. Implement source.Resolver.
//
//  2. Register against the purl type at Client setup:
//
//     c := pin.New(pin.ClientOptions{})
//     c.RegisterResolver("ipfs", myIPFSResolver)
//
// Manifest entries whose purl type matches dispatch to that resolver.
// pin.New registers the built-in npm, github, and generic resolvers;
// re-registering the same purl type replaces them.
//
// Plug-in resolvers populate the Resolved fields they have and leave
// the rest zero. pin treats missing optional fields (License,
// Attestation, etc.) as "unknown" rather than errors.
package source

import (
	"context"

	"github.com/git-pkgs/purl"
)

type Resolver interface {
	Resolve(ctx context.Context, p *purl.PURL, files []string) (*Resolved, error)
}

// Resolved is the unified output of a Resolver.
//
// Required: PURL, Name, Version, and a non-empty Files (each with
// Path, Integrity, Size, Content).
//
// Optional: PackageIntegrity (npm sha512 SRI, forge commit SHA, url
// SHA-384 SRI), License, SourceRepository, Attestation.
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

// Attestation holds SLSA Provenance v1 fields. Nil when the version
// was published without provenance.
type Attestation struct {
	PredicateType    string
	BuilderID        string
	SourceRepository string
	SourceRevision   string
	SignerIdentity   string
	BundleURL        string
}

type ResolvedFile struct {
	Path      string
	Integrity string
	Size      int64
	URL       string
	Content   []byte
}

// ProvenanceVerifier validates an attestation envelope against the
// claimed artifact bytes. bundleBody is raw DSSE/in-toto/sigstore
// JSON; digestAlg is "sha256" or "sha512"; digest is the raw artifact
// hash. source/sigstore is the built-in implementation; new verifiers
// (witness, SBOMit, plain in-toto) plug in without touching npm or
// forge.
type ProvenanceVerifier interface {
	VerifyBundle(ctx context.Context, bundleBody []byte, digestAlg string, digest []byte) error
}
