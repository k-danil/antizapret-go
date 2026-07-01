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

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
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
	}, newTestStore(t), cfg.MatcherRadix)
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r.Lookup("x.com"), "последний источник в списке выигрывает")
}

func TestLookupSubdomainsVsExact(t *testing.T) {
	r, err := NewRouter([]cfg.Matcher{
		{Name: "sub", Type: cfg.RouterTypeRemap, Source: writeList(t, "sub.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "ex", Type: cfg.RouterTypeBlackhole, Source: writeList(t, "exact.com"), Format: cfg.FormatPlain, Subdomains: new(false)},
	}, newTestStore(t), cfg.MatcherRadix)
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	require.Equal(t, matcher.ActionRemap, r.Lookup("a.sub.com"), "prefix-источник")
	require.Equal(t, matcher.ActionPass, r.Lookup("a.exact.com"), "exact-only источник")
	require.Equal(t, matcher.ActionBlackhole, r.Lookup("exact.com"))
}

func TestRebuildPruneOverridesSpecific(t *testing.T) {
	// source1 ремапит специфичный www.example.com; source2 (prune, позже) делает
	// весь .example.com passthrough — должен перебить специфичную запись.
	r, err := NewRouter([]cfg.Matcher{
		{Name: "remap", Type: cfg.RouterTypeRemap, Source: writeList(t, "www.example.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "override", Type: cfg.RouterTypePassthrough, Source: writeList(t, "example.com"), Format: cfg.FormatPlain, Subdomains: new(true), Prune: true},
	}, newTestStore(t), cfg.MatcherRadix)
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	require.Equal(t, matcher.ActionPass, r.Lookup("www.example.com"), "обрезано override-источником")
	require.Equal(t, matcher.ActionPass, r.Lookup("example.com"))
}

func TestRebuildEmptySourceFallsBackToCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte("x.com"), 0o600))

	r, err := NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + path, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, newTestStore(t), cfg.MatcherRadix)
	require.NoError(t, err)

	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r.Lookup("x.com"), "ремап после первого rebuild")

	// источник опустел — ребилд обязан откатиться на last-known-good снимок
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	require.NoError(t, r.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r.Lookup("x.com"), "пустой источник откатывается на кэш, не теряет домен")
}

// FST-бэкенд: ребилд компилирует и персистит matcher.fst, а новый роутер на той же
// дире стартует из него без сети (warm-start).
func TestFSTBackendPersistAndWarmStart(t *testing.T) {
	dir := t.TempDir()
	src := writeList(t, "blocked.test")

	mk := func() *Router {
		s, err := store.New(dir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		r, err := NewRouter([]cfg.Matcher{
			{Name: "bl", Type: cfg.RouterTypeRemap, Source: src, Format: cfg.FormatPlain, Subdomains: new(true)},
		}, s, cfg.MatcherFST)
		require.NoError(t, err)
		return r
	}

	r1 := mk()
	require.NoError(t, r1.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r1.Lookup("x.blocked.test"))

	r2 := mk()
	require.Greater(t, r2.LoadCached(), 0, "тёплый старт из персиста FST")
	require.Equal(t, matcher.ActionRemap, r2.Lookup("x.blocked.test"), "обслуживает из загруженного FST")
}

func fileSourceRouter(t *testing.T, st *store.Store, path string, m cfg.Matcher) *Router {
	t.Helper()
	m.Source = "file://" + path
	r, err := NewRouter([]cfg.Matcher{m}, st, cfg.MatcherFST)
	require.NoError(t, err)
	return r
}

// Переходы рефрешера по таблице состояний (run-файл) × событий (Fetch).
func TestRefreshSourceTransitions(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	path := filepath.Join(t.TempDir(), "list.txt")
	r := fileSourceRouter(t, st, path, cfg.Matcher{Name: "s", Type: cfg.RouterTypeRemap, Format: cfg.FormatPlain, Subdomains: new(true)})
	s := r.sources[0]

	res, err := s.refresh(ctx, st) // Absent + нет файла → Missing
	require.Error(t, err)
	require.Equal(t, refreshMissing, res)

	require.NoError(t, os.WriteFile(path, []byte("a.com\n"), 0o600))
	res, err = s.refresh(ctx, st) // Absent + Got → Updated
	require.NoError(t, err)
	require.Equal(t, refreshUpdated, res)

	res, err = s.refresh(ctx, st) // Cached + NotModified → Unchanged
	require.NoError(t, err)
	require.Equal(t, refreshUnchanged, res)

	require.NoError(t, os.WriteFile(path, []byte("a.com\nb.com\n"), 0o600))
	res, err = s.refresh(ctx, st) // Cached + Got (другой размер) → Updated
	require.NoError(t, err)
	require.Equal(t, refreshUpdated, res)

	require.NoError(t, os.Remove(path))
	res, err = s.refresh(ctx, st) // Cached + Fail → Stale (кэш цел)
	require.NoError(t, err)
	require.Equal(t, refreshStale, res)
}

// Смена правил парсинга (fingerprint) форсит перекачку даже при неизменном файле.
func TestRefreshSourceFingerprintForcesRefetch(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte("a.com\n"), 0o600))

	r1 := fileSourceRouter(t, st, path, cfg.Matcher{Name: "s", Type: cfg.RouterTypeRemap, Format: cfg.FormatPlain, Subdomains: new(true)})
	res, err := r1.sources[0].refresh(ctx, st)
	require.NoError(t, err)
	require.Equal(t, refreshUpdated, res)

	res, err = r1.sources[0].refresh(ctx, st) // тот же конфиг → NotModified
	require.NoError(t, err)
	require.Equal(t, refreshUnchanged, res)

	r2 := fileSourceRouter(t, st, path, cfg.Matcher{Name: "s", Type: cfg.RouterTypeRemap, Format: cfg.FormatPlain, Subdomains: new(true), Filter: &cfg.Filter{Exclude: []string{"nope.com"}}})
	res, err = r2.sources[0].refresh(ctx, st) // другой Filter → fingerprint разошёлся → форс
	require.NoError(t, err)
	require.Equal(t, refreshUpdated, res)
}

// Правим один источник из двух → только он Updated, второй не перечитан.
func TestRefreshIncremental(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	pa := filepath.Join(t.TempDir(), "a.txt")
	pb := filepath.Join(t.TempDir(), "b.txt")
	require.NoError(t, os.WriteFile(pa, []byte("a.com\n"), 0o600))
	require.NoError(t, os.WriteFile(pb, []byte("b.com\n"), 0o600))

	r, err := NewRouter([]cfg.Matcher{
		{Name: "a", Type: cfg.RouterTypeRemap, Source: "file://" + pa, Format: cfg.FormatPlain, Subdomains: new(true)},
		{Name: "b", Type: cfg.RouterTypeRemap, Source: "file://" + pb, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, st, cfg.MatcherFST)
	require.NoError(t, err)

	for _, s := range r.sources {
		res, e := s.refresh(ctx, st)
		require.NoError(t, e)
		require.Equal(t, refreshUpdated, res)
	}

	require.NoError(t, os.WriteFile(pa, []byte("a.com\nc.com\n"), 0o600)) // правим только A
	ra, err := r.sources[0].refresh(ctx, st)
	require.NoError(t, err)
	require.Equal(t, refreshUpdated, ra)
	rb, err := r.sources[1].refresh(ctx, st)
	require.NoError(t, err)
	require.Equal(t, refreshUnchanged, rb, "B не трогали → не перечитан")
}

// Повторный ребилд без изменений не пересобирает matcher.
func TestRebuildSkipsMergeWhenUnchanged(t *testing.T) {
	st := newTestStore(t)
	r, err := NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: writeList(t, "a.com"), Format: cfg.FormatPlain, Subdomains: new(true)},
	}, st, cfg.MatcherFST)
	require.NoError(t, err)

	require.NoError(t, r.Rebuild(context.Background()))
	first := r.m.Load()
	require.NotNil(t, first)

	require.NoError(t, r.Rebuild(context.Background()))
	require.Same(t, first, r.m.Load(), "ребилд без изменений не трогает matcher")
}

// Источник убрали из конфига → orphan-run снесён, FST пересобран без него.
func TestRebuildDropsRemovedSource(t *testing.T) {
	dir := t.TempDir()
	mA := cfg.Matcher{Name: "a", Type: cfg.RouterTypeRemap, Source: writeList(t, "a.com"), Format: cfg.FormatPlain, Subdomains: new(true)}
	mB := cfg.Matcher{Name: "b", Type: cfg.RouterTypeRemap, Source: writeList(t, "b.com"), Format: cfg.FormatPlain, Subdomains: new(true)}

	mk := func(ms ...cfg.Matcher) *Router {
		s, err := store.New(dir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		r, err := NewRouter(ms, s, cfg.MatcherFST)
		require.NoError(t, err)
		return r
	}

	r1 := mk(mA, mB)
	require.NoError(t, r1.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r1.Lookup("b.com"))

	r2 := mk(mA) // B убран
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

	mk := func(ms ...cfg.Matcher) *Router {
		s, err := store.New(dir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		r, err := NewRouter(ms, s, cfg.MatcherFST)
		require.NoError(t, err)
		return r
	}

	r1 := mk(mA, mB)
	require.NoError(t, r1.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionBlackhole, r1.Lookup("x.com"), "B последний → выигрывает")

	r2 := mk(mB, mA) // реордер: теперь последний — A
	require.Greater(t, r2.LoadCached(), 0, "тёплый старт из FST (старый порядок)")
	require.NoError(t, r2.Rebuild(context.Background()))
	require.Equal(t, matcher.ActionRemap, r2.Lookup("x.com"), "после реордера A последний → выигрывает")
}
