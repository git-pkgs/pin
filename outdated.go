package pin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/spdx"
	"github.com/git-pkgs/vers"
)

// unmaintainedThreshold is the LastPublish age above which a package
// is flagged as unmaintained in `pin outdated`. 365 days is a cold-
// enough signal that an actively-maintained library wouldn't trip it
// (most projects ship at least one patch a year), without flagging
// stable-on-purpose libraries (which tend to ship in the 2-3 year
// window). The threshold is informational, not a sync-blocker.
const unmaintainedThresholdDays = 365

// OutdatedOptions configures pin.Outdated / Client.Outdated.
type OutdatedOptions struct {
	Dir         string
	Lock        string
	RegistryURL string
}

// OutdatedReport is one row of pin.Outdated: the locked version
// against the registry's current state, with the most-severe finding
// surfaced via Severity (one of "ok" / "behind" / "deprecated" /
// "provenance-downgrade" / "yanked").
type OutdatedReport struct {
	Name                string
	Locked              string
	Latest              string
	Behind              bool
	AgeDays             int
	LastPublish         string
	Deprecated          string
	Yanked              bool
	ProvenanceDowngrade bool // locked had provenance, latest doesn't
	ProvenanceUpgrade   bool // locked didn't, latest does

	// LicenseLocked / LicenseLatest are the SPDX-normalised license
	// strings for the locked and latest versions. LicenseChange is
	// true when both are non-empty and normalised-differ — the user
	// should re-evaluate license compatibility before bumping.
	LicenseLocked string
	LicenseLatest string
	LicenseChange bool

	// Unmaintained is true when the package's last publish (any
	// version) is older than unmaintainedThresholdDays. Informational;
	// does not affect Severity or OutdatedExitCode.
	Unmaintained bool
}

const (
	SeverityOK                  = "ok"
	SeverityBehind              = "behind"
	SeverityDeprecated          = "deprecated"
	SeverityYanked              = "yanked"
	SeverityProvenanceDowngrade = "provenance-downgrade"
)

func (r *OutdatedReport) Severity() string {
	switch {
	case r.Yanked:
		return SeverityYanked
	case r.ProvenanceDowngrade:
		return SeverityProvenanceDowngrade
	case r.Deprecated != "":
		return SeverityDeprecated
	case r.Behind:
		return SeverityBehind
	default:
		return SeverityOK
	}
}

// Outdated is a one-shot shim around Client.Outdated.
func Outdated(ctx context.Context, opts OutdatedOptions) ([]OutdatedReport, error) {
	return New(ClientOptions{RegistryURL: opts.RegistryURL}).Outdated(ctx, opts)
}

// Outdated reports each lockfile entry's status against the registry's
// current state: behind, deprecated, yanked, or carrying a provenance
// downgrade/upgrade signal.
func (c *Client) Outdated(ctx context.Context, opts OutdatedOptions) ([]OutdatedReport, error) {
	if opts.Lock == "" {
		opts.Lock = DefaultLock
	}
	l, err := readLock(filepath.Join(opts.Dir, opts.Lock))
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, fmt.Errorf("%w at %s", ErrNoLockfile, filepath.Join(opts.Dir, opts.Lock))
	}

	src := c.NPM

	seen := map[string]bool{}
	var reports []OutdatedReport
	for _, a := range l.Assets {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true

		if !strings.HasPrefix(a.PURL, "pkg:npm/") {
			reports = append(reports, OutdatedReport{
				Name:   a.Name,
				Locked: a.Version,
			})
			continue
		}

		st, err := src.Status(ctx, a.Name, a.Version)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		nLocked, nLatest := normaliseLicense(st.License), normaliseLicense(st.LatestLicense)
		lastPublishAge := daysSince(st.LastPublish)
		reports = append(reports, OutdatedReport{
			Name:                a.Name,
			Locked:              a.Version,
			Latest:              st.Latest,
			Behind:              st.Latest != "" && vers.Compare(a.Version, st.Latest) < 0,
			AgeDays:             daysSince(st.LatestTime),
			LastPublish:         st.LastPublish,
			Deprecated:          st.Deprecated,
			Yanked:              st.Yanked,
			ProvenanceDowngrade: st.LockedHasProvenance && !st.LatestHasProvenance,
			ProvenanceUpgrade:   !st.LockedHasProvenance && st.LatestHasProvenance,
			LicenseLocked:       nLocked,
			LicenseLatest:       nLatest,
			LicenseChange:       nLocked != "" && nLatest != "" && nLocked != nLatest,
			Unmaintained:        lastPublishAge > unmaintainedThresholdDays,
		})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports, nil
}

// normaliseLicense runs the input through spdx's lax normaliser so two
// equivalent expressions ("MIT License" vs "MIT") compare equal. On
// any parser error the raw string is returned: the comparison falls
// back to literal equality, which is still useful when both inputs
// came from the same registry path.
func normaliseLicense(s string) string {
	if s == "" {
		return ""
	}
	if out, err := spdx.NormalizeExpressionLax(s); err == nil {
		return out
	}
	return s
}

func daysSince(iso string) int {
	if iso == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return -1
	}
	return int(time.Since(t).Hours() / 24) //nolint:mnd
}

const (
	ExitOutdated = 7
	ExitYanked   = 9
)

// OutdatedExitCode collapses a slice of OutdatedReport into the CLI
// exit code: ExitYanked (9) wins over ExitOutdated (7) wins over 0.
// Exported so library consumers driving the CLI from Go can mirror
// the exit-code semantics.
func OutdatedExitCode(reports []OutdatedReport) int {
	code := 0
	for _, r := range reports {
		switch {
		case r.Yanked:
			return ExitYanked
		case r.Behind, r.Deprecated != "":
			code = ExitOutdated
		}
	}
	return code
}
