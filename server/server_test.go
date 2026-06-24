package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/k-danil/antizapret-go/cfg"
	rtr "github.com/k-danil/antizapret-go/server/router"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/server/router/store"
	"github.com/stretchr/testify/require"
)

func TestWaitReadyWarmReturnsImmediately(t *testing.T) {
	s := &Server{warm: true, rebuildReady: make(chan struct{})}

	done := make(chan struct{})
	go func() { s.WaitReady(context.Background()); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "WaitReady на тёплом старте должен вернуться сразу")
	}
}

func TestWaitReadyColdBlocksUntilReady(t *testing.T) {
	s := &Server{rebuildReady: make(chan struct{})}

	done := make(chan struct{})
	go func() { s.WaitReady(context.Background()); close(done) }()

	select {
	case <-done:
		require.FailNow(t, "WaitReady на холодном старте должен ждать первый rebuild")
	case <-time.After(50 * time.Millisecond):
	}

	close(s.rebuildReady)
	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "WaitReady должен разблокироваться после закрытия rebuildReady")
	}
}

func TestWaitReadyColdReturnsOnCancel(t *testing.T) {
	s := &Server{rebuildReady: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() { s.WaitReady(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "WaitReady должен вернуться при отменённом ctx, не виснуть")
	}
}

func TestPolicyRebuilderInitialRebuildSignalsReady(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(listPath, []byte("blocked.test"), 0o600))

	st, err := store.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	sub := true
	router, err := rtr.NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + listPath, Format: cfg.FormatPlain, Subdomains: &sub},
	}, st, cfg.MatcherRadix)
	require.NoError(t, err)

	s := &Server{router: router, rebuildReady: make(chan struct{}), rebuildTimeout: 5 * time.Second}

	go s.PolicyRebuilder(t.Context(), time.Hour, nil)

	select {
	case <-s.rebuildReady:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "первый rebuild не просигналил rebuildReady")
	}

	require.Equal(t, matcher.ActionRemap, s.router.Lookup("blocked.test"), "первый rebuild загрузил правило")
}
