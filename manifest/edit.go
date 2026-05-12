package manifest

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

const yamlIndent = 2

// AddEntry inserts a new asset at its alphabetic position by name.
// Comments and surrounding YAML are preserved via the Node API.
func AddEntry(in io.Reader, out io.Writer, e Entry) error {
	if e.Name == "" {
		return fmt.Errorf("entry name is required")
	}
	if e.Version == "" {
		return fmt.Errorf("entry version is required")
	}
	doc, root, err := readDoc(in)
	if err != nil {
		return err
	}

	assets := findKey(root, "assets")
	if assets == nil {
		key := &yaml.Node{Kind: yaml.ScalarNode, Value: "assets"}
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		root.Content = append(root.Content, key, seq)
		assets = seq
	}
	if assets.Kind != yaml.SequenceNode {
		return fmt.Errorf("assets is not a sequence")
	}

	for _, n := range assets.Content {
		if k := findKey(n, keyName); k != nil && k.Value == e.Name {
			return fmt.Errorf("%s is already in the manifest", e.Name)
		}
	}

	entryNode, err := buildEntryNode(e)
	if err != nil {
		return err
	}

	assets.Content = append(assets.Content, entryNode)
	sort.SliceStable(assets.Content, func(i, j int) bool {
		ni, nj := findKey(assets.Content[i], keyName), findKey(assets.Content[j], keyName)
		if ni == nil || nj == nil {
			return false
		}
		return ni.Value < nj.Value
	})

	return writeValidated(out, doc)
}

// RemoveEntry removes the named asset, preserving comments and
// surrounding YAML.
func RemoveEntry(in io.Reader, out io.Writer, name string) error {
	doc, root, err := readDoc(in)
	if err != nil {
		return err
	}
	assets := findKey(root, "assets")
	if assets == nil || assets.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s is not in the manifest", name)
	}
	idx := -1
	for i, n := range assets.Content {
		if k := findKey(n, keyName); k != nil && k.Value == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("%s is not in the manifest", name)
	}
	assets.Content = append(assets.Content[:idx], assets.Content[idx+1:]...)
	return writeValidated(out, doc)
}

// writeValidated round-trips through Read to catch the case where
// AddEntry mutates a YAML mapping that's structurally valid but
// missing required fields (e.g. no `out:`): silent re-emission of
// something Read would reject is the bug class to prevent.
func writeValidated(out io.Writer, doc *yaml.Node) error {
	var buf bytes.Buffer
	if err := writeDoc(&buf, doc); err != nil {
		return err
	}
	if _, err := Read(bytes.NewReader(buf.Bytes())); err != nil {
		return fmt.Errorf("edit would produce invalid manifest: %w", err)
	}
	_, err := io.Copy(out, &buf)
	return err
}

func readDoc(in io.Reader) (*yaml.Node, *yaml.Node, error) {
	raw, err := io.ReadAll(in)
	if err != nil {
		return nil, nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse manifest: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil, fmt.Errorf("manifest is empty or not a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("manifest root must be a YAML mapping, got kind=%d", root.Kind)
	}
	return &doc, root, nil
}

func writeDoc(out io.Writer, doc *yaml.Node) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(yamlIndent)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	_, err := out.Write(buf.Bytes())
	return err
}

func buildEntryNode(e Entry) (*yaml.Node, error) {
	m := map[string]any{keyName: e.Name, keyVersion: e.Version}
	if e.RawSource != "" {
		m[keySource] = e.RawSource
	}
	if e.Files != nil {
		m[keyFiles] = e.Files
	}
	if e.Format != "" {
		m[keyFormat] = e.Format
	}
	var n yaml.Node
	if err := n.Encode(m); err != nil {
		return nil, err
	}
	orderKeys(&n, []string{keyName, keyVersion, keySource, keyFiles, keyFormat})
	return &n, nil
}

func orderKeys(n *yaml.Node, order []string) {
	if n.Kind != yaml.MappingNode {
		return
	}
	idx := map[string]int{}
	for i, k := range order {
		idx[k] = i
	}
	const pairWidth = 2
	type kv struct{ k, v *yaml.Node }
	pairs := make([]kv, 0, len(n.Content)/pairWidth)
	for i := 0; i < len(n.Content); i += pairWidth {
		pairs = append(pairs, kv{n.Content[i], n.Content[i+1]})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return idx[pairs[i].k.Value] < idx[pairs[j].k.Value]
	})
	n.Content = n.Content[:0]
	for _, p := range pairs {
		n.Content = append(n.Content, p.k, p.v)
	}
}

func findKey(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
