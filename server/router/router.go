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
	"github.com/k-danil/antizapret-go/utils"
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
	for _, m := range matchers {
		s := Source{Name: m.Name, URI: m.Source, Prune: m.Prune}

		switch m.Type {
		case cfg.RouterTypeBlackhole:
			s.Action = matcher.ActionBlackhole
		case cfg.RouterTypeRemap:
			s.Action = matcher.ActionRemap
		case cfg.RouterTypePassthrough:
			s.Action = matcher.ActionPass
		default:
			err = fmt.Errorf("unknown router type `%s` for source `%s`", m.Type, m.Name)
			return
		}

		subdomains := true
		if m.Subdomains != nil {
			subdomains = *m.Subdomains
		}

		if s.Parser, err = newParser(m, subdomains); err != nil {
			return
		}

		if s.Filter, err = newFilter(m); err != nil {
			return
		}

		sources = append(sources, s)
	}

	r = &Router{sources: sources, store: st, backend: backend}
	return
}

func (r *Router) Rebuild(ctx context.Context) (err error) {
	errs := make([]error, len(r.sources))
	var wg sync.WaitGroup
	for i := range r.sources {
		wg.Go(func() { errs[i] = r.refreshSource(ctx, r.sources[i]) })
	}
	wg.Wait()

	var all []error
	for _, e := range errs {
		if e != nil {
			all = append(all, e)
		}
	}

	box, fstData, n, cerr := r.compile()
	if cerr != nil {
		all = append(all, fmt.Errorf("compile matcher: %w", cerr))
	} else {
		r.m.Store(box)
		r.persistFST(fstData)
		log.L.Infow("router rebuilt", "length", n, "backend", string(r.backend))
	}

	if rerr := r.store.Retain(r.sourceNames()); rerr != nil {
		log.L.Warnw("failed to prune stale runs", "err", rerr)
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

// на сбое/пустом источнике run не перезаписываем — merge возьмёт прежний (last-known-good).
func (r *Router) refreshSource(ctx context.Context, s Source) error {
	entries, ferr := r.fetchSource(ctx, s)
	if ferr == nil && len(entries) > 0 {
		if werr := r.store.WriteRun(s.Name, store.Validator{}, toRecords(entries)); werr != nil {
			return fmt.Errorf("source `%s`: persist run: %w", s.Name, werr)
		}
		return nil
	}

	if r.store.HasRun(s.Name) {
		log.L.Warnw("source unusable, keeping cached run", "source", s.Name, "fetched", len(entries), "err", ferr)
		return nil
	}
	if ferr != nil {
		return fmt.Errorf("source `%s`: fetch failed (%w), no cache", s.Name, ferr)
	}
	log.L.Warnw("source returned empty, no cache to fall back on", "source", s.Name)
	return nil
}

func (r *Router) fetchSource(ctx context.Context, s Source) (entries []Entry, err error) {
	var rdr io.ReadCloser
	if rdr, err = s.GetReader(ctx); err != nil {
		err = fmt.Errorf("failed to get reader for source `%s`: %w", s.Name, err)
		return
	}
	defer func() { _ = rdr.Close() }()

	if err = s.Parser.Parse(rdr, func(e Entry) {
		domain := utils.NormalizeDomain(e.Domain)
		if domain == "" {
			log.L.Warnw("skipped entry in source", "entry", e.Domain, "source", s.Name)
			return
		}
		if !s.Filter.Keep(domain) {
			return
		}
		entries = append(entries, Entry{Domain: domain, Subdomains: e.Subdomains})
	}); err != nil {
		err = fmt.Errorf("failed to read source `%s`: %w", s.Name, err)
	}
	return
}

func toRecords(entries []Entry) []store.Record {
	recs := make([]store.Record, len(entries))
	for i, e := range entries {
		mode := byte(matcher.MatchExact)
		if e.Subdomains {
			mode = byte(matcher.MatchPrefix)
		}
		recs[i] = store.Record{Key: matcher.ReverseLabels(e.Domain), Mode: mode}
	}
	return recs
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
