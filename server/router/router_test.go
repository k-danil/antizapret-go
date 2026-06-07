package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/antizapret-vpn/go-proxy/cfg"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file://" + path
}

func TestRebuildLastSourceWins(t *testing.T) {
	r, err := NewRouter([]cfg.Matcher{
		{Name: "bl", Type: cfg.RouterTypeBlackhole, Source: writeList(t, "x.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "rm", Type: cfg.RouterTypeRemap, Source: writeList(t, "x.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
	}, newTestStore(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Lookup("x.com"); got != ActionRemap {
		t.Fatalf("Lookup = %v, want ActionRemap (last source in list wins)", got)
	}
}

func TestLookupSubdomainsVsExact(t *testing.T) {
	r, err := NewRouter([]cfg.Matcher{
		{Name: "sub", Type: cfg.RouterTypeRemap, Source: writeList(t, "sub.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "ex", Type: cfg.RouterTypeBlackhole, Source: writeList(t, "exact.com"), Format: cfg.FormatPlain, Subdomains: new(false)},
	}, newTestStore(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := r.Lookup("a.sub.com"); got != ActionRemap {
		t.Fatalf("a.sub.com = %v, want ActionRemap (prefix source)", got)
	}
	if got := r.Lookup("a.exact.com"); got != ActionPass {
		t.Fatalf("a.exact.com = %v, want ActionPass (exact-only source)", got)
	}
	if got := r.Lookup("exact.com"); got != ActionBlackhole {
		t.Fatalf("exact.com = %v, want ActionBlackhole", got)
	}
}

func TestRebuildPruneOverridesSpecific(t *testing.T) {
	// source1 ремапит специфичный www.example.com; source2 (prune, позже) делает
	// весь .example.com passthrough — должен перебить специфичную запись.
	r, err := NewRouter([]cfg.Matcher{
		{Name: "remap", Type: cfg.RouterTypeRemap, Source: writeList(t, "www.example.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "override", Type: cfg.RouterTypePassthrough, Source: writeList(t, "example.com"), Format: cfg.FormatPlain, Subdomains: new(true), Prune: true},
	}, newTestStore(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := r.Lookup("www.example.com"); got != ActionPass {
		t.Fatalf("www.example.com = %v, want ActionPass (pruned by override)", got)
	}
	if got := r.Lookup("example.com"); got != ActionPass {
		t.Fatalf("example.com = %v, want ActionPass", got)
	}
}

func TestRebuildEmptySourceFallsBackToCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("x.com"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + path, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, newTestStore(t))
	if err != nil {
		t.Fatal(err)
	}

	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Lookup("x.com") != ActionRemap {
		t.Fatal("x.com must be remapped after first rebuild")
	}

	// источник опустел — ребилд обязан откатиться на last-known-good снимок
	if err = os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = r.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Lookup("x.com") != ActionRemap {
		t.Fatal("empty source must fall back to cached snapshot, not drop the domain")
	}
}
