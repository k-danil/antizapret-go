package router

import (
	"errors"
	"path/filepath"
	"testing"
)

func entriesEqual(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]Entry{
		nil,
		{{Domain: "example.com", Subdomains: true}},
		{{Domain: "a.test", Subdomains: false}, {Domain: "xn--80ak6aa92e.com", Subdomains: true}},
	}
	for _, in := range cases {
		out, err := decodeEntries(encodeEntries(in))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !entriesEqual(in, out) {
			t.Fatalf("round-trip mismatch: %v -> %v", in, out)
		}
	}
}

func TestDecodeCorrupt(t *testing.T) {
	// заголовок заявляет домен длиной 5, но данных нет
	if _, err := decodeEntries([]byte{1, 0, 5}); err == nil {
		t.Fatal("expected error on truncated record")
	}
}

func TestStoreSaveLoad(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	entries := []Entry{{Domain: "a.test", Subdomains: true}, {Domain: "b.test", Subdomains: false}}
	if err = s.Save("src", entries); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load("src")
	if err != nil {
		t.Fatal(err)
	}
	if !entriesEqual(entries, got) {
		t.Fatalf("loaded %v, want %v", got, entries)
	}

	if _, err = s.Load("missing"); !errors.Is(err, errNotCached) {
		t.Fatalf("missing source err = %v, want errNotCached", err)
	}
}
