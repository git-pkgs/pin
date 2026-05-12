package manifest

import (
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"gopkg.in/yaml.v3"
)

type Layout string

const (
	LayoutNested Layout = "nested"
	LayoutFlat   Layout = "flat"
)

type Manifest struct {
	Out           string    `yaml:"out"`
	Layout        Layout    `yaml:"layout"`
	MinReleaseAge *Duration `yaml:"min_release_age"`
	Trust         *Trust    `yaml:"trust"`
	Assets        []Entry   `yaml:"assets"`
}

type Entry struct {
	Name          string    `yaml:"name"`
	Version       string    `yaml:"version"`
	RawSource     string    `yaml:"source"`
	Files         []string  `yaml:"files"`
	Format        string    `yaml:"format"`
	MinReleaseAge *Duration `yaml:"min_release_age"`
	Trust         *Trust    `yaml:"trust"`

	src Source
}

// Trust collects the provenance-verification policy for the manifest or
// for a single entry. Nil pointers on RequireProvenance and
// RequirePublisherMatchesRepository let the manifest default propagate;
// nil on the slice fields means "use the parent's list" rather than
// "explicitly empty."
type Trust struct {
	RequireProvenance                 *bool    `yaml:"require_provenance"`
	RequirePublisherMatchesRepository *bool    `yaml:"require_publisher_matches_repository"`
	TrustedIssuers                    []string `yaml:"trusted_issuers"`
	TrustedWorkflows                  []string `yaml:"trusted_workflows"`
}

// EffectiveTrust resolves the trust policy for an entry: per-entry
// scalar overrides win over the manifest top level; the slice fields
// merge (entry's plus manifest's, deduped).
func (m *Manifest) EffectiveTrust(e *Entry) Trust {
	var out Trust
	if m.Trust != nil {
		out = *m.Trust
	}
	if e.Trust == nil {
		return out
	}
	if e.Trust.RequireProvenance != nil {
		out.RequireProvenance = e.Trust.RequireProvenance
	}
	if e.Trust.RequirePublisherMatchesRepository != nil {
		out.RequirePublisherMatchesRepository = e.Trust.RequirePublisherMatchesRepository
	}
	out.TrustedIssuers = mergeUnique(out.TrustedIssuers, e.Trust.TrustedIssuers)
	out.TrustedWorkflows = mergeUnique(out.TrustedWorkflows, e.Trust.TrustedWorkflows)
	return out
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// BoolValue is a helper so callers can write t.Require(t.RequireProvenance)
// rather than dereference-and-default boilerplate.
func BoolValue(b *bool) bool {
	return b != nil && *b
}

// DefaultMinReleaseAge is the default cooldown window applied when the
// manifest doesn't specify one. Most malicious npm versions are caught
// within 24–48 hours; defaulting to 48h blocks the majority of
// fresh-publish supply-chain attacks at the cost of a bounded lag on
// bleeding-edge releases. Opt out per entry or globally with
// `min_release_age: 0`.
const DefaultMinReleaseAge = 48 * time.Hour

// EffectiveMinReleaseAge returns the cooldown to apply to an entry:
// per-entry override if set, manifest default if set, otherwise the
// global default.
func (m *Manifest) EffectiveMinReleaseAge(e *Entry) time.Duration {
	if e.MinReleaseAge != nil {
		return time.Duration(*e.MinReleaseAge)
	}
	if m.MinReleaseAge != nil {
		return time.Duration(*m.MinReleaseAge)
	}
	return DefaultMinReleaseAge
}

// Duration is a time.Duration that unmarshals from a YAML string like
// "48h", "30m", or "0".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Value == "" {
		return nil
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("min_release_age %q: %w", node.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

func Read(r io.Reader) (*Manifest, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if err := m.validate(raw); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate(raw []byte) error {
	if m.Out == "" {
		return fmt.Errorf("out is required")
	}
	switch m.Layout {
	case "":
		m.Layout = LayoutNested
	case LayoutNested, LayoutFlat:
	default:
		return fmt.Errorf("layout must be %q or %q, got %q", LayoutNested, LayoutFlat, m.Layout)
	}

	if err := strictAssets(raw); err != nil {
		return err
	}

	for i := range m.Assets {
		if err := m.Assets[i].validate(); err != nil {
			return fmt.Errorf("assets[%d] (%s): %w", i, m.Assets[i].Name, err)
		}
	}
	return nil
}

const (
	keyName    = "name"
	keyVersion = "version"
	keySource  = "source"
	keyFiles   = "files"
	keyFormat  = "format"
)

var allowedEntryKeys = map[string]bool{
	keyName:           true,
	keyVersion:        true,
	keySource:         true,
	keyFiles:          true,
	keyFormat:         true,
	"min_release_age": true,
	"trust":           true,
}

// strictAssets walks each asset's mapping node and rejects keys not in
// allowedEntryKeys. Top-level keys are not checked, so forward-compat
// additions like `trust:` don't break older binaries.
func strictAssets(raw []byte) error {
	var partial struct {
		Assets []yaml.Node `yaml:"assets"`
	}
	if err := yaml.Unmarshal(raw, &partial); err != nil {
		return err
	}
	for i, n := range partial.Assets {
		if n.Kind != yaml.MappingNode {
			return fmt.Errorf("assets[%d]: expected a mapping", i)
		}
		for k := 0; k < len(n.Content); k += 2 {
			key := n.Content[k].Value
			if !allowedEntryKeys[key] {
				return fmt.Errorf("assets[%d]: unknown field %q", i, key)
			}
		}
	}
	return nil
}

func (e *Entry) validate() error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	if e.Version == "" {
		return fmt.Errorf("version is required")
	}
	src, err := ParseSource(e.RawSource)
	if err != nil {
		return err
	}
	e.src = src

	if e.Files != nil && len(e.Files) == 0 {
		return fmt.Errorf("files: [] is empty; omit the field to use the package entry-point, or list at least one path")
	}
	for _, f := range e.Files {
		if err := validateFilePath(f); err != nil {
			return err
		}
	}
	return nil
}

func validateFilePath(p string) error {
	if p == "" {
		return fmt.Errorf("file path is empty")
	}
	if path.IsAbs(p) {
		return fmt.Errorf("file %q: absolute paths are not allowed", p)
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("file %q: escapes the package root", p)
	}
	return nil
}

func (e *Entry) Source() Source {
	if e.src.Kind == "" {
		s, err := ParseSource(e.RawSource)
		if err != nil {
			return Source{}
		}
		e.src = s
	}
	return e.src
}

// PURL returns the canonical purl for this entry at the given resolved version.
// npm: pkg:npm/[%40scope/]name@version
// forge: pkg:{forge}/owner/repo@version
// url: pkg:generic/name@version?download_url=...
func (e *Entry) PURL(resolvedVersion string) *purl.PURL {
	s := e.Source()
	switch s.Kind {
	case SourceForge:
		return purl.New(s.Forge, s.Owner, s.Repo, resolvedVersion, nil)
	case SourceURL:
		return purl.New("generic", "", e.Name, resolvedVersion, map[string]string{"download_url": s.URL})
	case SourceNPM:
		fallthrough
	default:
		ns, name := "", e.Name
		if strings.HasPrefix(name, "@") {
			ns, name, _ = strings.Cut(name, "/")
		}
		return purl.New("npm", ns, name, resolvedVersion, nil)
	}
}

func (e *Entry) Slug() string {
	if s := e.Source(); s.Kind == SourceForge && s.URL == "" {
		parts := []string{}
		if s.Owner != "" {
			parts = append(parts, strings.Split(s.Owner, "/")...)
		}
		parts = append(parts, s.Repo)
		return strings.Join(parts, "__")
	}
	name := strings.TrimPrefix(e.Name, "@")
	return strings.ReplaceAll(name, "/", "__")
}
