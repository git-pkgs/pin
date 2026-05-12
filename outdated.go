package pin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/spdx"
	"github.com/git-pkgs/vers"
)

// unmaintainedThresholdDays is informational, not a sync-blocker.
// 365 days is cold enough that actively-maintained libraries don't
// trip it while stable-on-purpose libraries (2-3 year cadence) do.
const unmaintainedThresholdDays = 365

type OutdatedOptions struct {
	Dir         string
	Lock        string
	RegistryURL string
}

// OutdatedReport is one row of pin.Outdated. Severity reports the
// most-severe finding: ok / behind / deprecated / provenance-downgrade
// / yanked.
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

	// LicenseLocked / LicenseLatest are SPDX-normalised. LicenseChange
	// is true when both are non-empty and differ; bumping should
	// re-evaluate license compatibility.
	LicenseLocked string
	LicenseLatest string
	LicenseChange bool

	// Unmaintained is informational; does not affect Severity or
	// OutdatedExitCode.
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

func Outdated(ctx context.Context, opts OutdatedOptions) ([]OutdatedReport, error) {
	return New(ClientOptions{RegistryURL: opts.RegistryURL}).Outdated(ctx, opts)
}

// Outdated reports each lockfile entry's status against the
// registry's current state.
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

		p, perr := purl.Parse(a.PURL)
		if perr != nil {
			return nil, fmt.Errorf("%s: parse purl %q: %w", a.Name, a.PURL, perr)
		}
		st, err := src.Status(ctx, p)
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

// normaliseLicense falls back to the raw string on parser error so
// two registry-supplied expressions still compare literally when
// SPDX normalisation can't help.
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

// OutdatedExitCode collapses reports into the CLI exit code:
// ExitYanked (9) > ExitOutdated (7) > 0.
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
