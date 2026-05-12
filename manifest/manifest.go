package manifest

import (
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/git-pkgs/cooldown"
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
	Name           string    `yaml:"name"`
	Version        string    `yaml:"version"`
	RawSource      string    `yaml:"source"`
	Files          []string  `yaml:"files"`
	Format         string    `yaml:"format"`
	MinReleaseAge  *Duration `yaml:"min_release_age"`
	Trust          *Trust    `yaml:"trust"`
	StripSourcemap bool      `yaml:"strip_sourcemap"`

	// RegistryURL overrides the default npm registry for this entry.
	// Honoured by the npm source kind; encoded as a `repository_url`
	// qualifier on the resolved purl so it round-trips into pin.lock.
	RegistryURL string `yaml:"registry_url"`

	src Source
}

// Trust. Nil pointers let the manifest default propagate; nil
// TrustedWorkflows means "inherit from parent" rather than "empty".
type Trust struct {
	RequireProvenance                 *bool    `yaml:"require_provenance"`
	RequirePublisherMatchesRepository *bool    `yaml:"require_publisher_matches_repository"`
	TrustedWorkflows                  []string `yaml:"trusted_workflows"`
}

// EffectiveTrust: per-entry scalars override manifest scalars;
// TrustedWorkflows merges across both, deduped.
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

func BoolValue(b *bool) bool {
	return b != nil && *b
}

// DefaultMinReleaseAge: 48h catches most malicious npm publishes
// (typically detected within 24–48h) while keeping the bleeding-edge
// lag bounded. Opt out per entry or globally with `min_release_age: 0`.
const DefaultMinReleaseAge = 48 * time.Hour

// Cooldown builds a cooldown.Config from the manifest's
// min_release_age. Default falls back to DefaultMinReleaseAge.
// Per-entry overrides become Packages entries keyed by the entry's
// package purl without a version.
func (m *Manifest) Cooldown() *cooldown.Config {
	cfg := &cooldown.Config{Default: durationStr(m.MinReleaseAge, DefaultMinReleaseAge)}
	for i := range m.Assets {
		e := &m.Assets[i]
		if e.MinReleaseAge == nil {
			continue
		}
		key := e.PURL("").String()
		if cfg.Packages == nil {
			cfg.Packages = map[string]string{}
		}
		cfg.Packages[key] = time.Duration(*e.MinReleaseAge).String()
	}
	return cfg
}

func durationStr(d *Duration, fallback time.Duration) string {
	if d == nil {
		return fallback.String()
	}
	return time.Duration(*d).String()
}

// Duration unmarshals from a YAML string like "48h", "30m", or "0".
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
	"strip_sourcemap": true,
	"registry_url":    true,
}

// strictAssets rejects unknown keys per asset. Top-level keys are
// not checked so forward-compat additions don't break older binaries.
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

// PURL returns the canonical purl for this entry.
//
//	npm:   pkg:npm/[%40scope/]name@version[?repository_url=...]
//	forge: pkg:{forge}/owner/repo@version
//	url:   pkg:generic/name@version?download_url=...
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
		var qualifiers map[string]string
		if e.RegistryURL != "" {
			qualifiers = map[string]string{"repository_url": e.RegistryURL}
		}
		return purl.New("npm", ns, name, resolvedVersion, qualifiers)
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
