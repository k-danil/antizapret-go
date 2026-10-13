package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/server/router/store"
	"github.com/stretchr/testify/require"
)

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return "file://" + path
}

func newFSTRouter(t *testing.T, dir string, ms ...cfg.Matcher) *Router {
	t.Helper()
	s, err := store.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	r, err := NewRouter(ms, s, cfg.MatcherFST)
	require.NoError(t, err)
	return r
}

// Источник убрали из конфига → orphan-run снесён, FST пересобран без него.
func TestRebuildDropsRemovedSource(t *testing.T) {
	dir := t.TempDir()
	mA := cfg.Matcher{Name: "a", Type: cfg.RouterTypeRemap, Source: writeList(t, "a.com"), Format: cfg.FormatPlain, Subdomains: new(true)}
	mB := cfg.Matcher{Name: "b", Type: cfg.RouterTypeRemap, Source: writeList(t, "b.com"), Format: cfg.FormatPlain, Subdomains: new(true)}

	r1 := newFSTRouter(t, dir, mA, mB)
	require.NoError(t, r1.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r1.Lookup("b.com"))

	r2 := newFSTRouter(t, dir, mA) // B убран
	require.Greater(t, r2.LoadCached(), 0, "тёплый старт из FST (ещё с B)")
	require.Equal(t, matcher.ActionRemap, r2.Lookup("b.com"), "до ребилда FST содержит B")
	require.NoError(t, r2.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionPass, r2.Lookup("b.com"), "removed>0 пересобрал FST без B")
	require.Equal(t, matcher.ActionRemap, r2.Lookup("a.com"))
}

// Перестановка источников на тёплом старте меняет приоритет last-wins (idx в fingerprint).
func TestRebuildReorderFlipsPriority(t *testing.T) {
	dir := t.TempDir()
	src := writeList(t, "x.com")
	mA := cfg.Matcher{Name: "a", Type: cfg.RouterTypeRemap, Source: src, Format: cfg.FormatPlain, Subdomains: new(true)}
	mB := cfg.Matcher{Name: "b", Type: cfg.RouterTypeBlackhole, Source: src, Format: cfg.FormatPlain, Subdomains: new(true)}

	r1 := newFSTRouter(t, dir, mA, mB)
	require.NoError(t, r1.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionBlackhole, r1.Lookup("x.com"), "B последний → выигрывает")

	r2 := newFSTRouter(t, dir, mB, mA) // реордер: теперь последний — A
	require.Greater(t, r2.LoadCached(), 0, "тёплый старт из FST (старый порядок)")
	require.NoError(t, r2.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r2.Lookup("x.com"), "после реордера A последний → выигрывает")
}
