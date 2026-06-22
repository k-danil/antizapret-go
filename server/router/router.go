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
	"github.com/k-danil/antizapret-go/utils"
)

type Router struct {
	sources []Source
	store   *Store
	backend cfg.MatcherBackend

	m atomic.Pointer[matcherBox]
}

type matcherBox struct{ matcher.Matcher }

func NewRouter(matchers []cfg.Matcher, store *Store, backend cfg.MatcherBackend) (r *Router, err error) {
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

	r = &Router{sources: sources, store: store, backend: backend}
	return
}

// Rebuild best-effort: сбойный/пустой источник откатывается на last-known-good из store.
func (r *Router) Rebuild(ctx context.Context) (err error) {
	// источники тянутся параллельно, но в radix вставляются в исходном порядке —
	// last-wins и prune зависят от порядка.
	results := make([]sourceResult, len(r.sources))
	var wg sync.WaitGroup
	for i := range r.sources {
		wg.Go(func() { results[i] = r.loadSource(ctx, r.sources[i]) })
	}
	wg.Wait()

	radix := matcher.NewRadix[matcher.Action]()
	var (
		length int
		errs   []error
	)
	for i, s := range r.sources {
		if results[i].err != nil {
			errs = append(errs, results[i].err)
		}
		insertEntries(radix, s.Action, s.Prune, results[i].entries)
		length += len(results[i].entries)
	}

	box, cerr := r.compile(radix)
	if cerr != nil {
		errs = append(errs, fmt.Errorf("compile matcher: %w", cerr))
	} else {
		r.m.Store(box)
		log.L.Infow("router rebuilt", "length", length, "backend", string(r.backend))
	}

	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

func (r *Router) compile(rx *matcher.Radix[matcher.Action]) (*matcherBox, error) {
	// пустой бэкенд → FST (дефолт)
	switch r.backend {
	case cfg.MatcherRadix:
		return &matcherBox{matcher.NewRadixMatcher(rx)}, nil
	default:
		m, err := matcher.NewFSTMatcher(rx)
		if err != nil {
			return nil, err
		}
		return &matcherBox{m}, nil
	}
}

type sourceResult struct {
	entries []Entry
	err     error
}

// loadSource тянет источник; на сбое или подозрительно пустом ответе откатывается
// на last-known-good из store, чтобы транзиентная проблема источника не меняла
// поведение прокси.
func (r *Router) loadSource(ctx context.Context, s Source) sourceResult {
	entries, ferr := r.fetchSource(ctx, s)
	if ferr == nil && len(entries) > 0 {
		if serr := r.store.Save(s.Name, entries); serr != nil {
			log.L.Warnw("failed to persist source cache", "source", s.Name, "err", serr)
		}
		return sourceResult{entries: entries}
	}

	cached, lerr := r.store.Load(s.Name)
	if lerr != nil {
		if ferr != nil {
			return sourceResult{err: fmt.Errorf("source `%s`: fetch failed (%w), no cache (%v)", s.Name, ferr, lerr)}
		}
		log.L.Warnw("source returned empty, no cache to fall back on", "source", s.Name)
		return sourceResult{}
	}
	log.L.Warnw("source unusable, using cached entries", "source", s.Name, "fetched", len(entries), "err", ferr)
	return sourceResult{entries: cached}
}

// LoadCached строит radix только из кэша; 0 => холодный старт (кэша нет).
func (r *Router) LoadCached() (n int) {
	radix := matcher.NewRadix[matcher.Action]()
	for _, s := range r.sources {
		entries, err := r.store.Load(s.Name)
		if err != nil {
			continue
		}
		insertEntries(radix, s.Action, s.Prune, entries)
		n += len(entries)
	}
	if n > 0 {
		box, err := r.compile(radix)
		if err != nil {
			log.L.Warnw("failed to compile cached matcher", "err", err)
			return 0
		}
		r.m.Store(box)
	}
	return
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

func insertEntries(radix *matcher.Radix[matcher.Action], action matcher.Action, prune bool, entries []Entry) {
	for _, e := range entries {
		mode := matcher.MatchExact
		if e.Subdomains {
			mode = matcher.MatchPrefix
		}
		radix.Insert(e.Domain, action, mode)
		if prune {
			radix.PruneBelow(e.Domain)
		}
	}
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
