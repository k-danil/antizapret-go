package utils

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestRadix_MatchModes(t *testing.T) {
	r := NewRadix[int]()

	r.Insert("", 100, MatchPrefix)

	r.Insert("google.com", 1, MatchExact)
	r.Insert("mail.google.com", 2, MatchExact)

	r.Insert("example.com", 10, MatchPrefix)
	r.Insert("api.example.com", 11, MatchPrefix)
	r.Insert("a.b.c", 20, MatchPrefix)

	tests := []struct {
		key   string
		wantV int
		ok    bool
	}{

		{"google.com", 1, true},
		{"mail.google.com", 2, true},

		{"api.example.com", 11, true},
		{"v1.api.example.com", 11, true},
		{"example.com", 10, true},
		{"x.example.com", 10, true},

		{"unknown.tld", 0, false},

		{"", 0, false},

		{"a.b.c", 20, true},
		{"x.a.b.c", 20, true},
		{"ab.c", 0, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("get_%s", tt.key), func(t *testing.T) {
			got, ok := r.Get(tt.key)
			if ok != tt.ok {
				t.Fatalf("ok mismatch for %q: got %v want %v", tt.key, ok, tt.ok)
			}
			if ok && got != tt.wantV {
				t.Fatalf("value mismatch for %q: got %v want %v", tt.key, got, tt.wantV)
			}
		})
	}
}

func TestRadix_SplitsAndOverwrites(t *testing.T) {
	r := NewRadix[string]()

	r.Insert("abc", "v1", MatchExact)
	r.Insert("abcd", "v2", MatchExact)
	r.Insert("abx", "v3", MatchExact)
	r.Insert("ab", "pv", MatchPrefix)

	cases := []struct {
		key   string
		want  string
		found bool
	}{
		{"abc", "v1", true},
		{"abcd", "v2", true},
		{"abx", "v3", true},
		{"abzzz", "pv", true},
		{"ab", "pv", true},
		{"a", "", false},
		{"", "", false},
	}

	for _, c := range cases {
		t.Run("check_"+c.key, func(t *testing.T) {
			v, ok := r.Get(c.key)
			if ok != c.found {
				t.Fatalf("ok mismatch %q: got %v want %v", c.key, ok, c.found)
			}
			if ok && v != c.want {
				t.Fatalf("value mismatch %q: got %q want %q", c.key, v, c.want)
			}
		})
	}

	r.Insert("abc", "v1_overwrite", MatchExact)
	if v, ok := r.Get("abc"); !ok || v != "v1_overwrite" {
		t.Fatalf("overwrite failed: got (%v,%v), want (v1_overwrite,true)", v, ok)
	}
}

func BenchmarkRadix_Get_Simple(b *testing.B) {
	r := NewRadix[int]()

	r.Insert("", 0, MatchPrefix)
	r.Insert("google.com", 1, MatchExact)
	r.Insert("mail.google.com", 2, MatchExact)
	r.Insert("example.com", 3, MatchPrefix)
	r.Insert("api.example.com", 4, MatchPrefix)

	keys := []string{
		"google.com",
		"mail.google.com",
		"api.example.com",
		"v1.api.example.com",
		"unknown.tld",
		"example.com",
		"x.example.com",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := keys[i%len(keys)]
		_, _ = r.Get(k)
	}
}

func BenchmarkRadix_Get_Long(b *testing.B) {
	r := NewRadix[int]()

	base := "abcdefghijklmnopqrstuvwxyz0123456789"
	makeDomain := func(n int) string {

		out := make([]byte, 0, n+n/10)
		for i := 0; i < n; i++ {
			out = append(out, base[i%len(base)])
			if (i+1)%10 == 0 && i != n-1 {
				out = append(out, '.')
			}
		}
		return string(out)
	}

	longExact := make([]string, 0, 64)
	longPrefix := make([]string, 0, 64)
	for i := 20; i < 84; i += 4 {
		longExact = append(longExact, makeDomain(i))
	}
	for i := 16; i < 80; i += 8 {
		longPrefix = append(longPrefix, makeDomain(i))
	}

	for i, s := range longExact {
		r.Insert(s, i, MatchExact)
	}
	for i, s := range longPrefix {
		r.Insert(s, i, MatchPrefix)
	}

	var queries []string
	queries = append(queries, longExact...)
	queries = append(queries, longPrefix...)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(queries), func(i, j int) { queries[i], queries[j] = queries[j], queries[i] })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := queries[i%len(queries)]
		_, _ = r.Get(k)
	}
}
