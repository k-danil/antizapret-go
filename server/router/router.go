package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/utils"
)

type Router struct {
	sources []Source
	store   *Store

	r atomic.Pointer[utils.Radix[Action]]
}

type Action uint8

const (
	ActionBlackhole Action = iota
	ActionRemap
	ActionPass
)

func NewRouter(matchers []cfg.Matcher, store *Store) (r *Router, err error) {
	sources := make([]Source, 0, len(matchers))
	for _, m := range matchers {
		s := Source{Name: m.Name, URI: m.Source}

		switch m.Type {
		case cfg.RouterTypeBlackhole:
			s.Action = ActionBlackhole
		case cfg.RouterTypeRemap:
			s.Action = ActionRemap
		case cfg.RouterTypePassthrough:
			s.Action = ActionPass
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

	r = &Router{sources: sources, store: store}
	return
}

// Rebuild — best-effort: сбойный или пустой источник заменяется его last-known-good
// снимком из store, остальные обновляются; radix подменяется атомарно.
func (r *Router) Rebuild(ctx context.Context) (err error) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()

	radix := utils.NewRadix[Action]()

	var (
		length int
		errs   []error
	)
	for _, s := range r.sources {
		entries, ferr := r.fetchSource(ctx, s)
		if ferr == nil && len(entries) > 0 {
			if serr := r.store.Save(s.Name, entries); serr != nil {
				log.L.Warnw("failed to persist source cache", "source", s.Name, "err", serr)
			}
		} else {
			// сбой или подозрительно пустой ответ — откатываемся на last-known-good,
			// чтобы транзиентная проблема источника не меняла поведение прокси
			var lerr error
			var cached []Entry
			if cached, lerr = r.store.Load(s.Name); lerr != nil {
				if ferr != nil {
					errs = append(errs, fmt.Errorf("source `%s`: fetch failed (%w), no cache (%v)", s.Name, ferr, lerr))
					continue
				}
				log.L.Warnw("source returned empty, no cache to fall back on", "source", s.Name)
			} else {
				log.L.Warnw("source unusable, using cached entries",
					"source", s.Name, "fetched", len(entries), "err", ferr)
				entries = cached
			}
		}

		insertEntries(radix, s.Action, entries)
		length += len(entries)
	}

	r.r.Store(radix)
	log.L.Infow("router rebuilt", "length", length)

	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

// LoadCached собирает radix только из персистентного кэша, без сети — для
// быстрого старта. Возвращает число загруженных записей (0 => холодный старт).
func (r *Router) LoadCached() (n int) {
	radix := utils.NewRadix[Action]()
	for _, s := range r.sources {
		entries, err := r.store.Load(s.Name)
		if err != nil {
			continue
		}
		insertEntries(radix, s.Action, entries)
		n += len(entries)
	}
	if n > 0 {
		r.r.Store(radix)
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

func insertEntries(radix *utils.Radix[Action], action Action, entries []Entry) {
	for _, e := range entries {
		mode := utils.MatchExact
		if e.Subdomains {
			mode = utils.MatchPrefix
		}
		radix.Insert(e.Domain, action, mode)
	}
}

func (r *Router) Lookup(domain string) (action Action) {
	radix := r.r.Load()
	if radix == nil {
		return ActionPass
	}
	var ok bool
	if action, ok = radix.Get(domain); !ok {
		action = ActionPass
	}
	return
}
