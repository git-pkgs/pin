package pin

import "errors"

// Sentinel errors for branching with errors.Is.
//
// CLI exit-code mapping:
//
//	ErrFrozenDrift, ErrVerifyFailed             → exit 4
//	ErrProvenanceMissing, ErrPublisherMismatch  → exit 4
//	OutdatedExitCode handles yanked / behind / deprecated → 7 or 9
var (
	ErrNoLockfile = errors.New("no lockfile; run sync first")

	ErrFrozenDrift = errors.New("manifest and lockfile disagree")

	ErrVerifyFailed = errors.New("verify failed")

	ErrProvenanceMissing = errors.New("no attestation recorded")

	// ErrPublisherMismatch fires when the attestation's
	// source_repository does not match the package's declared
	// repository.url and no trusted_workflows entry matches.
	ErrPublisherMismatch = errors.New("attestation source repository mismatch")

	ErrPathEscape = errors.New("output path escapes out directory")

	// ErrPathCollision fires when two resolved assets in the same
	// Sync produce the same on-disk Out. Most common under
	// layout: flat when two packages or two files within one entry
	// share a basename. pin fails closed rather than silently
	// overwriting.
	ErrPathCollision = errors.New("two assets resolve to the same output path")
)
