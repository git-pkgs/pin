package integrity

import "testing"

const benchSRI = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"

func BenchmarkParseSRI(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = ParseSRI(benchSRI)
	}
}

func BenchmarkFormatSRI(b *testing.B) {
	_, hex, _ := ParseSRI(benchSRI)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = FormatSRI("SHA-384", hex)
	}
}
