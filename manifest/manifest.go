package manifest

import (
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type Layout string

const (
	LayoutNested Layout = "nested"
	LayoutFlat   Layout = "flat"
)

type Manifest struct {
	Out    string  `yaml:"out"`
	Layout Layout  `yaml:"layout"`
	Assets []Entry `yaml:"assets"`
}

type Entry struct {
	Name      string   `yaml:"name"`
	Version   string   `yaml:"version"`
	RawSource string   `yaml:"source"`
	Files     []string `yaml:"files"`
	Format    string   `yaml:"format"`

	src Source
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
	if len(m.Assets) == 0 {
		return fmt.Errorf("at least one asset is required")
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
	keyName:    true,
	keyVersion: true,
	keySource:  true,
	keyFiles:   true,
	keyFormat:  true,
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
