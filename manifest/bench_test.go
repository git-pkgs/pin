package manifest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func makeManifest(n int) string {
	var sb strings.Builder
	sb.WriteString("out: \"v\"\nassets:\n")
	for i := range n {
		fmt.Fprintf(&sb, "  - name: \"pkg-%04d\"\n    version: \"^1.0\"\n    files: [\"dist/x.js\"]\n", i)
	}
	return sb.String()
}

func BenchmarkRead9(b *testing.B)    { benchRead(b, 9) }
func BenchmarkRead100(b *testing.B)  { benchRead(b, 100) }
func BenchmarkRead1000(b *testing.B) { benchRead(b, 1000) }

func benchRead(b *testing.B, n int) {
	b.Helper()
	src := makeManifest(n)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = Read(strings.NewReader(src))
	}
}

func BenchmarkAddEntry100(b *testing.B) {
	src := makeManifest(100)
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		i++
		var out bytes.Buffer
		_ = AddEntry(strings.NewReader(src), &out, Entry{
			Name:    fmt.Sprintf("new-pkg-%d", i),
			Version: "1.0.0",
			Files:   []string{"dist/x.js"},
		})
	}
}
