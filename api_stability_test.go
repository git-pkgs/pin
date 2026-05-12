package pin_test

import (
	"testing"

	pin "github.com/git-pkgs/pin"
	"github.com/git-pkgs/pin/lock"
	"github.com/git-pkgs/pin/manifest"
	"github.com/git-pkgs/pin/pinfs"
)

// TestPublicAPIStability is a compile-time guard rail: it references
// every public symbol pin commits to keeping stable across minor
// releases. Removing, renaming, or changing the type of any of these
// is a breaking change and must ship under a new major version.
//
// The test never fails at runtime; the value is in the build error
// that surfaces when an exported symbol is missing.
func TestPublicAPIStability(t *testing.T) {
	t.Parallel()

	// Top-level functions.
	_ = pin.New
	_ = pin.Sync
	_ = pin.Add
	_ = pin.Outdated
	_ = pin.OutdatedExitCode
	_ = pin.Verify
	_ = pin.Remove
	_ = pin.List
	_ = pin.Path
	_ = pin.Init
	_ = pin.SBOM
	_ = pin.EncodeLock

	// Configuration and result types.
	var _ pin.ClientOptions
	var _ pin.Client
	var _ pin.SyncOptions
	var _ pin.SyncResult
	var _ pin.AddOptions
	var _ pin.AddResult
	var _ pin.OutdatedOptions
	var _ pin.OutdatedReport
	var _ pin.VerifyOptions
	var _ pin.VerifyResult
	var _ pin.Drift
	var _ pin.ListEntry
	var _ pin.SBOMOptions
	var _ pin.SBOMFormat

	// Sentinel errors. Callers branch with errors.Is.
	_ = pin.ErrNoLockfile
	_ = pin.ErrFrozenDrift
	_ = pin.ErrVerifyFailed
	_ = pin.ErrProvenanceMissing
	_ = pin.ErrPublisherMismatch
	_ = pin.ErrPathEscape
	_ = pin.ErrPathCollision

	// Constants.
	_ = pin.DefaultManifest
	_ = pin.DefaultLock
	_ = pin.ToolName
	_ = pin.ToolVersion
	_ = pin.SeverityOK
	_ = pin.SeverityBehind
	_ = pin.SeverityDeprecated
	_ = pin.SeverityYanked
	_ = pin.SeverityProvenanceDowngrade
	_ = pin.ExitOutdated
	_ = pin.ExitYanked
	_ = pin.SBOMCycloneDXJSON
	_ = pin.SBOMCycloneDXXML
	_ = pin.SBOMSPDXJSON

	// pinfs sub-package: the writable-filesystem abstraction.
	_ = pinfs.OS
	_ = pinfs.NewMemory
	var _ pinfs.Writer
	var _ pinfs.Memory

	// lock sub-package.
	var _ lock.Lock
	var _ lock.Asset
	var _ lock.Attestation
	var _ lock.Changes
	_ = lock.Read
	_ = lock.Write
	_ = lock.Diff

	// manifest sub-package.
	var _ manifest.Manifest
	var _ manifest.Entry
	var _ manifest.Trust
	var _ manifest.Source
	_ = manifest.Read
	_ = manifest.AddEntry
	_ = manifest.RemoveEntry
	_ = manifest.ParseSource
}
