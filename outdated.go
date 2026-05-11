package pin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/git-pkgs/pin/source/npm"
	"github.com/git-pkgs/vers"
)

type OutdatedOptions struct {
	Dir         string
	Lock        string
	RegistryURL string
}

type OutdatedReport struct {
	Name        string
	Locked      string
	Latest      string
	Behind      bool
	AgeDays     int
	LastPublish string
	Deprecated  string
	Yanked      bool
}

const (
	SeverityOK         = "ok"
	SeverityBehind     = "behind"
	SeverityDeprecated = "deprecated"
	SeverityYanked     = "yanked"
)

func (r *OutdatedReport) Severity() string {
	switch {
	case r.Yanked:
		return SeverityYanked
	case r.Deprecated != "":
		return SeverityDeprecated
	case r.Behind:
		return SeverityBehind
	default:
		return SeverityOK
	}
}

func Outdated(ctx context.Context, opts OutdatedOptions) ([]OutdatedReport, error) {
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

	src := npm.New(npm.Options{RegistryURL: opts.RegistryURL})

	seen := map[string]bool{}
	var reports []OutdatedReport
	for _, a := range l.Assets {
		if seen[a.Name] {
			continue
		}
		seen[a.Name] = true

		st, err := src.Status(ctx, a.Name, a.Version)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		reports = append(reports, OutdatedReport{
			Name:        a.Name,
			Locked:      a.Version,
			Latest:      st.Latest,
			Behind:      st.Latest != "" && vers.Compare(a.Version, st.Latest) < 0,
			AgeDays:     daysSince(st.LatestTime),
			LastPublish: st.LastPublish,
			Deprecated:  st.Deprecated,
			Yanked:      st.Yanked,
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
