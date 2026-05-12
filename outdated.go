package pin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/vers"
)

type OutdatedOptions struct {
	Dir         string
	Lock        string
	RegistryURL string
}

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
		return nil, fmt.Errorf("no lockfile at %s; run sync first", filepath.Join(opts.Dir, opts.Lock))
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
		})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports, nil
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
