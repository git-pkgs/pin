package pin

import "errors"

// Sentinel errors. Operations wrap these so callers can branch on
// failure mode with errors.Is rather than string-matching.
//
// CLI exit-code mapping uses these sentinels:
//
//	ErrFrozenDrift, ErrVerifyFailed             → exit 4
//	ErrProvenanceMissing, ErrPublisherMismatch  → exit 4
//	OutdatedExitCode handles ErrYanked / behind / deprecated → 7 or 9
var (
	// ErrNoLockfile is returned when an operation requires a lockfile
	// (verify, outdated, sync --frozen, sync --no-fetch) but none
	// exists on disk.
	ErrNoLockfile = errors.New("no lockfile; run sync first")

	// ErrFrozenDrift is returned by sync --frozen and sync --no-fetch
	// when the manifest and lockfile disagree: an entry is in one but
	// not the other, or the locked version no longer satisfies the
	// manifest constraint.
	ErrFrozenDrift = errors.New("manifest and lockfile disagree")

	// ErrVerifyFailed wraps a verify result with drifts or missing
	// files. Granular per-asset state lives on VerifyResult.Drifted /
	// .Missing; callers that just want to branch on "verify is
	// unhappy" use errors.Is(err, ErrVerifyFailed).
	ErrVerifyFailed = errors.New("verify failed")

	// ErrProvenanceMissing is returned by enforceTrust when
	// --strict-provenance (or trust.require_provenance) is set and an
	// asset has no recorded attestation.
	ErrProvenanceMissing = errors.New("no attestation recorded")

	// ErrPublisherMismatch is returned by enforceTrust when
	// --require-publisher-matches-repository (or trust.
	// require_publisher_matches_repository) fires: the attestation's
	// source repository does not match the package's declared
	// repository.url and no trusted_workflows entry matches.
	ErrPublisherMismatch = errors.New("attestation source repository mismatch")

	// ErrPathEscape is returned by safeOut when a joined output path
	// would land outside the manifest's out directory. Defence in
	// depth: the manifest validator rejects most shapes upstream, but
	// any path that slips through is caught here before any bytes hit
	// disk.
	ErrPathEscape = errors.New("output path escapes out directory")
)
