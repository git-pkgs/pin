package lock

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"

	"github.com/git-pkgs/integrity"
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

// Struct fields below are ordered by their JSON tag name. That makes
// encoding/json's natural output order canonical (json.Marshal emits
// struct fields in source order; map keys it sorts alphabetically; the
// SBOM has no maps). Skipping the previous Marshal → Unmarshal-to-any
// → Re-encode round-trip drops ~half the lock.Write allocations at
// 1000-asset scale. The "Keys sorted alphabetically within every
// object" guarantee in SPEC.md is preserved by holding this ordering
// invariant — any new field must be inserted in alphabetical position.
type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	Components  []cdxComponent `json:"components"`
	Metadata    cdxMetadata    `json:"metadata"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
}

type cdxMetadata struct {
	Properties []cdxProperty `json:"properties,omitempty"`
	Tools      cdxTools      `json:"tools"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

type cdxComponent struct {
	BOMRef             string         `json:"bom-ref"`
	Components         []cdxComponent `json:"components,omitempty"`
	Evidence           *cdxEvidence   `json:"evidence,omitempty"`
	ExternalReferences []cdxExtRef    `json:"externalReferences,omitempty"`
	Hashes             []cdxHash      `json:"hashes,omitempty"`
	Licenses           []cdxLicense   `json:"licenses,omitempty"`
	Name               string         `json:"name"`
	Properties         []cdxProperty  `json:"properties,omitempty"`
	PURL               string         `json:"purl,omitempty"`
	Type               string         `json:"type"`
	Version            string         `json:"version,omitempty"`
}

type cdxEvidence struct {
	Identity []cdxIdentity `json:"identity,omitempty"`
}

type cdxIdentity struct {
	Field   string               `json:"field"`
	Methods []cdxIdentityMethod  `json:"methods,omitempty"`
	Tools   []cdxIdentityToolRef `json:"tools,omitempty"`
}

type cdxIdentityMethod struct {
	Confidence string `json:"confidence,omitempty"`
	Technique  string `json:"technique"`
	Value      string `json:"value,omitempty"`
}

type cdxIdentityToolRef struct {
	Ref string `json:"ref"`
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
	if hashes := encodePackageHashes(first.PackageIntegrity); len(hashes) > 0 {
		c.Hashes = hashes
	}
	if first.License != "" {
		c.Licenses = []cdxLicense{{License: cdxLicenseID{ID: first.License}}}
	}
	if first.Repository != "" {
		c.ExternalReferences = []cdxExtRef{{Type: "vcs", URL: first.Repository}}
	}
	if first.Attestation != nil {
		c.Properties = append(c.Properties, attestationProperties(first.Attestation)...)
		if first.Attestation.BundleURL != "" {
			c.ExternalReferences = append(c.ExternalReferences, cdxExtRef{Type: "attestation", URL: first.Attestation.BundleURL})
		}
	}
	for _, a := range assets {
		c.Components = append(c.Components, fileComponent(purl, a))
	}
	return c
}

const (
	propPredicateType    = "pin:attestation.predicate_type"
	propBuilderID        = "pin:attestation.builder_id"
	propSourceRepository = "pin:attestation.source_repository"
	propSourceRevision   = "pin:attestation.source_revision"
	propSignerIdentity   = "pin:attestation.signer_identity"
)

func attestationProperties(a *Attestation) []cdxProperty {
	var p []cdxProperty
	if a.PredicateType != "" {
		p = append(p, cdxProperty{Name: propPredicateType, Value: a.PredicateType})
	}
	if a.BuilderID != "" {
		p = append(p, cdxProperty{Name: propBuilderID, Value: a.BuilderID})
	}
	if a.SourceRepository != "" {
		p = append(p, cdxProperty{Name: propSourceRepository, Value: a.SourceRepository})
	}
	if a.SourceRevision != "" {
		p = append(p, cdxProperty{Name: propSourceRevision, Value: a.SourceRevision})
	}
	if a.SignerIdentity != "" {
		p = append(p, cdxProperty{Name: propSignerIdentity, Value: a.SignerIdentity})
	}
	return p
}

func readAttestation(props []cdxProperty, refs []cdxExtRef) *Attestation {
	a := &Attestation{
		PredicateType:    findProp(props, propPredicateType),
		BuilderID:        findProp(props, propBuilderID),
		SourceRepository: findProp(props, propSourceRepository),
		SourceRevision:   findProp(props, propSourceRevision),
		SignerIdentity:   findProp(props, propSignerIdentity),
		BundleURL:        findExtRef(refs, "attestation"),
	}
	if a.PredicateType == "" && a.BuilderID == "" && a.BundleURL == "" {
		return nil
	}
	return a
}

func fileComponent(parentPURL string, a Asset) cdxComponent {
	ref := parentPURL + "#" + a.Path
	c := cdxComponent{
		Type:   "file",
		BOMRef: ref,
		Name:   a.Path,
	}
	if a.Integrity != "" {
		if hashes := encodeSRIHashes(a.Integrity); len(hashes) > 0 {
			c.Hashes = hashes
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
		pkgIntegrity, err := decodePackageHashes(pkg.Hashes)
		if err != nil {
			return nil, fmt.Errorf("package %q integrity: %w", pkg.Name, err)
		}
		var license string
		if len(pkg.Licenses) > 0 {
			license = pkg.Licenses[0].License.ID
		}
		srcRepo := findExtRef(pkg.ExternalReferences, "vcs")
		attestation := readAttestation(pkg.Properties, pkg.ExternalReferences)
		for _, file := range pkg.Components {
			a := Asset{
				Name:             pkg.Name,
				Version:          pkg.Version,
				PURL:             pkg.PURL,
				PackageIntegrity: pkgIntegrity,
				License:          license,
				Repository:       srcRepo,
				Attestation:      attestation,
				Path:             file.Name,
				Out:              findProp(file.Properties, propOut),
				Type:             findProp(file.Properties, propType),
				Format:           findProp(file.Properties, propFormat),
				URL:              findExtRef(file.ExternalReferences, "distribution"),
			}
			fileIntegrity, err := decodeSRIHashes(file.Hashes)
			if err != nil {
				return nil, fmt.Errorf("file %q integrity: %w", file.Name, err)
			}
			a.Integrity = fileIntegrity
			if s := findProp(file.Properties, propSize); s != "" {
				a.Size, _ = strconv.ParseInt(s, 10, 64)
			}
			l.Assets = append(l.Assets, a)
		}
	}
	return l, nil
}

func encodeSRIHashes(value string) []cdxHash {
	digests, err := integrity.ParseSRI(value)
	if err != nil {
		return nil
	}
	hashes := make([]cdxHash, 0, len(digests))
	for _, digest := range digests {
		hashes = append(hashes, cdxHash{
			Alg:     cdxAlgorithm(digest.Algorithm()),
			Content: digest.Hex(),
		})
	}
	return hashes
}

func decodeSRIHashes(hashes []cdxHash) (string, error) {
	digests := make(integrity.SRI, 0, len(hashes))
	for _, hash := range hashes {
		algorithm, ok := sriAlgorithm(hash.Alg)
		if !ok {
			continue
		}
		digest, err := integrity.ParseHex(algorithm, hash.Content)
		if err != nil {
			return "", fmt.Errorf("invalid %s digest: %w", hash.Alg, err)
		}
		digests = append(digests, digest)
	}
	return integrity.FormatSRI(digests), nil
}

func cdxAlgorithm(algorithm integrity.Algorithm) string {
	switch algorithm {
	case integrity.SHA256:
		return "SHA-256"
	case integrity.SHA384:
		return "SHA-384"
	case integrity.SHA512:
		return "SHA-512"
	default:
		return ""
	}
}

func sriAlgorithm(algorithm string) (integrity.Algorithm, bool) {
	switch algorithm {
	case "SHA-256":
		return integrity.SHA256, true
	case "SHA-384":
		return integrity.SHA384, true
	case "SHA-512":
		return integrity.SHA512, true
	default:
		return 0, false
	}
}

// encodePackageHashes converts Asset.PackageIntegrity, either an SRI metadata
// list from npm or a bare commit SHA from a forge source, into CycloneDX hash
// entries. Forge SHAs remain SHA-1 values local to pin.
func encodePackageHashes(pkgIntegrity string) []cdxHash {
	if pkgIntegrity == "" {
		return nil
	}
	if hashes := encodeSRIHashes(pkgIntegrity); len(hashes) > 0 {
		return hashes
	}
	if isCommitSHA(pkgIntegrity) {
		return []cdxHash{{Alg: "SHA-1", Content: pkgIntegrity}}
	}
	return nil
}

// decodePackageHashes is the inverse of encodePackageHashes. SHA-1 entries
// remain bare commit values, while supported SRI digests stay in list order.
func decodePackageHashes(hashes []cdxHash) (string, error) {
	var commitSHA string
	var sriHashes []cdxHash
	for _, hash := range hashes {
		if hash.Alg == "SHA-1" {
			if !isCommitSHA(hash.Content) {
				return "", fmt.Errorf("invalid SHA-1 commit digest %q", hash.Content)
			}
			if commitSHA == "" {
				commitSHA = hash.Content
			}
			continue
		}
		if _, ok := sriAlgorithm(hash.Alg); ok {
			sriHashes = append(sriHashes, hash)
		}
	}
	if len(sriHashes) > 0 {
		return decodeSRIHashes(sriHashes)
	}
	return commitSHA, nil
}

func isCommitSHA(s string) bool {
	const commitSHALen = 40
	if len(s) != commitSHALen {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
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
