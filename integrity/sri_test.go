package integrity

import "testing"

func TestParseSRI(t *testing.T) {
	cases := []struct {
		in      string
		wantAlg string
		wantHex string
		wantErr bool
	}{
		{"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC", "SHA-384", "a2a56e01f5d129aa7b7dd81c098e6eca433af91f46a90f0afeec72f6bc7b1cd42519897590fcd0868d70c7827063cc02", false},
		{"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "SHA-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", "SHA-512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", false},
		{"", "", "", true},
		{"sha384-not!base64", "", "", true},
		{"md5-abc", "", "", true},
		{"sha384", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			alg, hex, err := ParseSRI(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if alg != tc.wantAlg {
				t.Errorf("alg = %q, want %q", alg, tc.wantAlg)
			}
			if hex != tc.wantHex {
				t.Errorf("hex = %q, want %q", hex, tc.wantHex)
			}
		})
	}
}

func TestSRIRoundTrip(t *testing.T) {
	in := "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	alg, hex, err := ParseSRI(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := FormatSRI(alg, hex)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round-trip: %q != %q", out, in)
	}
}

func TestParseSRIMultipleReturnsFirstDigest(t *testing.T) {
	input := "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU= sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	algorithm, digest, err := ParseSRI(input)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != CDXSHA256 {
		t.Errorf("algorithm = %q, want %q", algorithm, CDXSHA256)
	}
	if digest != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("digest = %q", digest)
	}
}
