package lock

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func makeLock(n int) *Lock {
	const tarballSRI = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	const fileSRI = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	l := &Lock{OutDir: "v"}
	for i := range n {
		name := fmt.Sprintf("pkg-%04d", i)
		l.Assets = append(l.Assets, Asset{
			Name:             name,
			Version:          "1.0.0",
			PURL:             fmt.Sprintf("pkg:npm/%s@1.0.0", name),
			Type:             "script",
			Format:           "iife",
			Path:             "dist/index.min.js",
			Out:              name + "/index.min.js",
			URL:              fmt.Sprintf("https://cdn.jsdelivr.net/npm/%s@1.0.0/dist/index.min.js", name),
			Integrity:        fileSRI,
			Size:             50000,
			PackageIntegrity: tarballSRI,
			License:          "MIT",
		})
	}
	return l
}

func BenchmarkWrite9(b *testing.B)    { benchWrite(b, 9) }
func BenchmarkWrite100(b *testing.B)  { benchWrite(b, 100) }
func BenchmarkWrite1000(b *testing.B) { benchWrite(b, 1000) }

func benchWrite(b *testing.B, n int) {
	b.Helper()
	l := makeLock(n)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var buf bytes.Buffer
		_ = Write(&buf, l, "pin", "bench")
	}
}

func BenchmarkRead9(b *testing.B)    { benchRead(b, 9) }
func BenchmarkRead100(b *testing.B)  { benchRead(b, 100) }
func BenchmarkRead1000(b *testing.B) { benchRead(b, 1000) }

func benchRead(b *testing.B, n int) {
	b.Helper()
	var buf bytes.Buffer
	_ = Write(&buf, makeLock(n), "pin", "bench")
	encoded := buf.String()
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = Read(strings.NewReader(encoded))
	}
}
