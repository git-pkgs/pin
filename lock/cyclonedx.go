package lock

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/git-pkgs/pin/integrity"
)

const (
	cdxBOMFormat   = "CycloneDX"
	cdxSpecVersion = "1.6"

	propLockfileVersion = "pin:lockfile_version"
	propOutDir          = "pin:out_dir"
	propOut             = "pin:out"
	propType            = "pin:type"
	propFormat          = "pin:format"
	propSize            = "pin:size"
)

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Tools      cdxTools      `json:"tools"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type               string         `json:"type"`
	BOMRef             string         `json:"bom-ref"`
	Name               string         `json:"name"`
	Version            string         `json:"version,omitempty"`
	PURL               string         `json:"purl,omitempty"`
	Hashes             []cdxHash      `json:"hashes,omitempty"`
	Licenses           []cdxLicense   `json:"licenses,omitempty"`
	ExternalReferences []cdxExtRef    `json:"externalReferences,omitempty"`
	Properties         []cdxProperty  `json:"properties,omitempty"`
	Components         []cdxComponent `json:"components,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxLicense struct {
	License cdxLicenseID `json:"license"`
}

type cdxLicenseID struct {
	ID string `json:"id"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func toCDX(l *Lock, toolName, toolVersion string) cdxBOM {
	bom := cdxBOM{
		BOMFormat:   cdxBOMFormat,
		SpecVersion: cdxSpecVersion,
		Version:     1,
		Metadata: cdxMetadata{
			Tools: cdxTools{Components: []cdxToolComponent{{Type: "application", Name: toolName, Version: toolVersion}}},
			Properties: []cdxProperty{
				{Name: propLockfileVersion, Value: strconv.Itoa(Version)},
			},
		},
	}
	if l.OutDir != "" {
		bom.Metadata.Properties = append(bom.Metadata.Properties, cdxProperty{Name: propOutDir, Value: l.OutDir})
	}

	byPkg := map[string][]Asset{}
	var pkgKeys []string
	for _, a := range l.Assets {
		key := a.PURL
		if _, seen := byPkg[key]; !seen {
			pkgKeys = append(pkgKeys, key)
		}
		byPkg[key] = append(byPkg[key], a)
	}
	slices.Sort(pkgKeys)

	for _, purl := range pkgKeys {
		assets := byPkg[purl]
		slices.SortFunc(assets, func(a, b Asset) int { return cmp.Compare(a.Path, b.Path) })
		bom.Components = append(bom.Components, packageComponent(purl, assets))
	}
	return bom
}

func packageComponent(purl string, assets []Asset) cdxComponent {
	first := assets[0]
	c := cdxComponent{
		Type:    "library",
		BOMRef:  purl,
		Name:    first.Name,
		Version: first.Version,
		PURL:    purl,
	}
	if first.PackageIntegrity != "" {
		if alg, hex, err := integrity.ParseSRI(first.PackageIntegrity); err == nil {
			c.Hashes = []cdxHash{{Alg: alg, Content: hex}}
		}
	}
	if first.License != "" {
		c.Licenses = []cdxLicense{{License: cdxLicenseID{ID: first.License}}}
	}
	if first.SourceRepository != "" {
		c.ExternalReferences = []cdxExtRef{{Type: "vcs", URL: first.SourceRepository}}
	}
	for _, a := range assets {
		c.Components = append(c.Components, fileComponent(purl, a))
	}
	return c
}

func fileComponent(parentPURL string, a Asset) cdxComponent {
	ref := parentPURL + "#" + a.Path
	c := cdxComponent{
		Type:   "file",
		BOMRef: ref,
		Name:   a.Path,
	}
	if a.Integrity != "" {
		if alg, hex, err := integrity.ParseSRI(a.Integrity); err == nil {
			c.Hashes = []cdxHash{{Alg: alg, Content: hex}}
		}
	}
	if a.URL != "" {
		c.ExternalReferences = []cdxExtRef{{Type: "distribution", URL: a.URL}}
	}
	props := []cdxProperty{{Name: propOut, Value: a.Out}}
	if a.Type != "" {
		props = append(props, cdxProperty{Name: propType, Value: a.Type})
	}
	if a.Format != "" {
		props = append(props, cdxProperty{Name: propFormat, Value: a.Format})
	}
	if a.Size > 0 {
		props = append(props, cdxProperty{Name: propSize, Value: strconv.FormatInt(a.Size, 10)})
	}
	c.Properties = props
	return c
}

func fromCDX(bom *cdxBOM) (*Lock, error) {
	l := &Lock{
		LockfileVersion: Version,
		GeneratedBy:     toolString(bom),
		OutDir:          findProp(bom.Metadata.Properties, propOutDir),
	}
	for _, pkg := range bom.Components {
		var pkgIntegrity string
		if len(pkg.Hashes) > 0 {
			if sri, err := integrity.FormatSRI(pkg.Hashes[0].Alg, pkg.Hashes[0].Content); err == nil {
				pkgIntegrity = sri
			}
		}
		var license string
		if len(pkg.Licenses) > 0 {
			license = pkg.Licenses[0].License.ID
		}
		srcRepo := findExtRef(pkg.ExternalReferences, "vcs")
		for _, file := range pkg.Components {
			a := Asset{
				Name:             pkg.Name,
				Version:          pkg.Version,
				PURL:             pkg.PURL,
				PackageIntegrity: pkgIntegrity,
				License:          license,
				SourceRepository: srcRepo,
				Path:             file.Name,
				Out:              findProp(file.Properties, propOut),
				Type:             findProp(file.Properties, propType),
				Format:           findProp(file.Properties, propFormat),
				URL:              findExtRef(file.ExternalReferences, "distribution"),
			}
			if len(file.Hashes) > 0 {
				if sri, err := integrity.FormatSRI(file.Hashes[0].Alg, file.Hashes[0].Content); err == nil {
					a.Integrity = sri
				}
			}
			if s := findProp(file.Properties, propSize); s != "" {
				a.Size, _ = strconv.ParseInt(s, 10, 64)
			}
			l.Assets = append(l.Assets, a)
		}
	}
	return l, nil
}

func toolString(bom *cdxBOM) string {
	if len(bom.Metadata.Tools.Components) == 0 {
		return ""
	}
	t := bom.Metadata.Tools.Components[0]
	return t.Name + " " + t.Version
}

func findProp(ps []cdxProperty, name string) string {
	for _, p := range ps {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func findExtRef(refs []cdxExtRef, kind string) string {
	for _, r := range refs {
		if r.Type == kind {
			return r.URL
		}
	}
	return ""
}
