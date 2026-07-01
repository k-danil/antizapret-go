package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/server/router/store"
	"github.com/k-danil/antizapret-go/utils"
)

type Source struct {
	Name        string
	Action      matcher.Action
	Parser      Parser
	Filter      *Filter
	Prune       bool
	Fingerprint string
	fetcher     fetcher
}

func newSource(m cfg.Matcher, idx int) (s Source, err error) {
	s = Source{Name: m.Name, Prune: m.Prune}

	switch m.Type {
	case cfg.RouterTypeBlackhole:
		s.Action = matcher.ActionBlackhole
	case cfg.RouterTypeRemap:
		s.Action = matcher.ActionRemap
	case cfg.RouterTypePassthrough:
		s.Action = matcher.ActionPass
	case cfg.RouterTypeNXDomain:
		s.Action = matcher.ActionNXDomain
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
	if s.fetcher, err = newFetcher(m.Source); err != nil {
		err = fmt.Errorf("source `%s`: %w", m.Name, err)
		return
	}
	s.Fingerprint = fingerprint(m, subdomains, idx)
	return
}

// action/prune/idx включены намеренно: их смена даёт mismatch → пересборку (иначе
// skip-merge отдал бы stale). idx — позиция в конфиге (приоритет last-wins/prune):
// ловит реордер/вставку источников на тёплом старте.
// TODO: idx форсит лишнюю перекачку сдвинутых источников (нужен лишь re-merge) —
// заменить на build-signature или «первый ребилд всегда мёржит».
func fingerprint(m cfg.Matcher, subdomains bool, idx int) string {
	var re string
	if m.Regexp != nil {
		re = fmt.Sprintf("%+v", *m.Regexp)
	}
	var ex string
	if m.Filter != nil {
		ex = strings.Join(m.Filter.Exclude, "\x00")
	}
	s := fmt.Sprintf("uri=%s\x00fmt=%s\x00sub=%t\x00type=%s\x00prune=%t\x00idx=%d\x00re=%s\x00ex=%s",
		m.Source, m.Format, subdomains, m.Type, m.Prune, idx, re, ex)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type refreshResult uint8

const (
	refreshUnchanged refreshResult = iota
	refreshUpdated
	refreshStale
	refreshMissing
)

// На сбое/пустом ответе run не перезаписываем — merge возьмёт прежний (last-known-good).
func (s *Source) refresh(ctx context.Context, st *store.Store) (refreshResult, error) {
	prev, lerr := st.LoadValidator(s.Name)
	cached := lerr == nil
	if !cached || prev.Fingerprint != s.Fingerprint {
		prev = store.Validator{} // нет кэша или конфиг источника сменился → полный fetch
	}

	res, ferr := s.fetcher.fetch(ctx, prev)
	if ferr == nil && res.NotModified {
		return refreshUnchanged, nil
	}
	if ferr == nil {
		entries, perr := s.parse(res.Reader)
		_ = res.Reader.Close()
		switch {
		case perr != nil:
			ferr = perr
		case len(entries) > 0:
			v := res.Validator
			v.Fingerprint = s.Fingerprint
			if werr := st.WriteRun(s.Name, v, toRecords(entries)); werr != nil {
				return refreshStale, fmt.Errorf("source `%s`: persist run: %w", s.Name, werr)
			}
			return refreshUpdated, nil
		}
	}

	if cached {
		log.L.Warnw("source unusable, keeping cached run", "source", s.Name, "err", ferr)
		return refreshStale, nil
	}
	if ferr != nil {
		return refreshMissing, fmt.Errorf("source `%s`: fetch failed (%w), no cache", s.Name, ferr)
	}
	log.L.Warnw("source returned empty, no cache to fall back on", "source", s.Name)
	return refreshMissing, nil
}

func (s *Source) parse(rdr io.Reader) (entries []Entry, err error) {
	err = s.Parser.Parse(rdr, func(e Entry) {
		domain := utils.NormalizeDomain(e.Domain)
		if domain == "" {
			log.L.Warnw("skipped entry in source", "entry", e.Domain, "source", s.Name)
			return
		}
		if !s.Filter.Keep(domain) {
			return
		}
		entries = append(entries, Entry{Domain: domain, Subdomains: e.Subdomains})
	})
	if err != nil {
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
