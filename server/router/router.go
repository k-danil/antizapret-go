package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/server/router/store"
)

type Router struct {
	sources []Source
	store   *store.Store
	backend cfg.MatcherBackend

	m atomic.Pointer[matcherBox]
}

type matcherBox struct{ matcher.Matcher }

func NewRouter(matchers []cfg.Matcher, st *store.Store, backend cfg.MatcherBackend) (r *Router, err error) {
	sources := make([]Source, 0, len(matchers))
	for i, m := range matchers {
		var s Source
		if s, err = newSource(m, i); err != nil {
			return
		}
		sources = append(sources, s)
	}

	r = &Router{sources: sources, store: st, backend: backend}
	return
}

func (r *Router) Rebuild(ctx context.Context) (err error) {
	results := make([]refreshResult, len(r.sources))
	errs := make([]error, len(r.sources))
	var wg sync.WaitGroup
	for i := range r.sources {
		wg.Go(func() { results[i], errs[i] = r.sources[i].refresh(ctx, r.store) })
	}
	wg.Wait()

	var all []error
	anyUpdated := false
	for i := range results {
		if errs[i] != nil {
			all = append(all, errs[i])
		}
		if results[i] == refreshUpdated {
			anyUpdated = true
		}
	}

	removed, rerr := r.store.Retain(r.sourceNames())
	if rerr != nil {
		log.L.Warnw("failed to prune stale runs", "err", rerr)
	}

	if anyUpdated || removed > 0 || r.m.Load() == nil {
		box, fstData, n, cerr := r.compile()
		if cerr != nil {
			all = append(all, fmt.Errorf("compile matcher: %w", cerr))
		} else {
			r.m.Store(box)
			r.persistFST(fstData)
			log.L.Infow("router rebuilt", "length", n, "backend", string(r.backend))
		}
	}

	if len(all) > 0 {
		err = errors.Join(all...)
	}
	return
}

func (r *Router) LoadCached() int {
	if r.backend != cfg.MatcherRadix {
		if data, lerr := r.store.LoadFST(); lerr == nil {
			if m, merr := matcher.LoadFST(data); merr == nil {
				r.m.Store(&matcherBox{m})
				return len(data)
			}
		}
	}

	box, fstData, n, err := r.compile()
	if err != nil || n == 0 {
		return 0
	}
	r.m.Store(box)
	r.persistFST(fstData)
	return n
}

func (r *Router) compile() (box *matcherBox, fstData []byte, n int, err error) {
	srcs, closers := r.openRuns()
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	var m matcher.Matcher
	switch r.backend {
	case cfg.MatcherRadix:
		if m, n, err = matcher.BuildRadix(srcs); err != nil {
			return
		}
	default:
		if m, fstData, n, err = matcher.BuildFST(srcs); err != nil {
			return
		}
	}
	box = &matcherBox{m}
	return
}

func (r *Router) openRuns() (srcs []matcher.RunSource, closers []io.Closer) {
	for _, s := range r.sources {
		_, rr, oerr := r.store.OpenRun(s.Name)
		if oerr != nil {
			continue
		}
		closers = append(closers, rr)
		srcs = append(srcs, matcher.RunSource{
			Action: s.Action,
			Prune:  s.Prune,
			Next: func() ([]byte, matcher.MatchMode, bool) {
				rec, ok, nerr := rr.Next()
				if nerr != nil || !ok {
					return nil, 0, false
				}
				return rec.Key, matcher.MatchMode(rec.Mode), true
			},
		})
	}
	return
}

func (r *Router) persistFST(data []byte) {
	if data == nil {
		return
	}
	if err := r.store.SaveFST(data); err != nil {
		log.L.Warnw("failed to persist FST", "err", err)
	}
}

func (r *Router) sourceNames() []string {
	names := make([]string, len(r.sources))
	for i, s := range r.sources {
		names[i] = s.Name
	}
	return names
}

func (r *Router) Lookup(domain string) matcher.Action {
	box := r.m.Load()
	if box == nil {
		return matcher.ActionPass
	}
	return box.Lookup(domain)
}

func (r *Router) Ready() bool {
	return r.m.Load() != nil
}
