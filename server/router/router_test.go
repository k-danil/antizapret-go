package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/k-danil/antizapret-go/cfg"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return "file://" + path
}

func TestRebuildLastSourceWins(t *testing.T) {
	r, err := NewRouter([]cfg.Matcher{
		{Name: "bl", Type: cfg.RouterTypeBlackhole, Source: writeList(t, "x.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "rm", Type: cfg.RouterTypeRemap, Source: writeList(t, "x.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
	}, newTestStore(t))
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, ActionRemap, r.Lookup("x.com"), "последний источник в списке выигрывает")
}

func TestLookupSubdomainsVsExact(t *testing.T) {
	r, err := NewRouter([]cfg.Matcher{
		{Name: "sub", Type: cfg.RouterTypeRemap, Source: writeList(t, "sub.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "ex", Type: cfg.RouterTypeBlackhole, Source: writeList(t, "exact.com"), Format: cfg.FormatPlain, Subdomains: new(false)},
	}, newTestStore(t))
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	require.Equal(t, ActionRemap, r.Lookup("a.sub.com"), "prefix-источник")
	require.Equal(t, ActionPass, r.Lookup("a.exact.com"), "exact-only источник")
	require.Equal(t, ActionBlackhole, r.Lookup("exact.com"))
}

func TestRebuildPruneOverridesSpecific(t *testing.T) {
	// source1 ремапит специфичный www.example.com; source2 (prune, позже) делает
	// весь .example.com passthrough — должен перебить специфичную запись.
	r, err := NewRouter([]cfg.Matcher{
		{Name: "remap", Type: cfg.RouterTypeRemap, Source: writeList(t, "www.example.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "override", Type: cfg.RouterTypePassthrough, Source: writeList(t, "example.com"), Format: cfg.FormatPlain, Subdomains: new(true), Prune: true},
	}, newTestStore(t))
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	require.Equal(t, ActionPass, r.Lookup("www.example.com"), "обрезано override-источником")
	require.Equal(t, ActionPass, r.Lookup("example.com"))
}

func TestRebuildEmptySourceFallsBackToCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte("x.com"), 0o600))

	r, err := NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + path, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, newTestStore(t))
	require.NoError(t, err)

	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, ActionRemap, r.Lookup("x.com"), "ремап после первого rebuild")

	// источник опустел — ребилд обязан откатиться на last-known-good снимок
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, ActionRemap, r.Lookup("x.com"), "пустой источник откатывается на кэш, не теряет домен")
}
