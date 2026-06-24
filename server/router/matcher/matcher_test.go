package matcher

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type testEntry struct {
	domain     string
	subdomains bool
}

type testSource struct {
	action  Action
	prune   bool
	entries []testEntry
}

func testMode(sub bool) MatchMode {
	if sub {
		return MatchPrefix
	}
	return MatchExact
}

func runSources(srcs []testSource) []RunSource {
	out := make([]RunSource, len(srcs))
	for si, s := range srcs {
		type rec struct {
			key  []byte
			mode MatchMode
		}
		recs := make([]rec, 0, len(s.entries))
		for _, e := range s.entries {
			recs = append(recs, rec{key: ReverseLabels(e.domain), mode: testMode(e.subdomains)})
		}
		sort.Slice(recs, func(i, j int) bool { return bytes.Compare(recs[i].key, recs[j].key) < 0 })
		i := 0
		out[si] = RunSource{
			Action: s.action,
			Prune:  s.prune,
			Next: func() ([]byte, MatchMode, bool) {
				if i >= len(recs) {
					return nil, 0, false
				}
				r := recs[i]
				i++
				return r.key, r.mode, true
			},
		}
	}
	return out
}

// oracle — независимый эталон прямым перебором по спеке: longest-suffix + last-wins,
// prune убирает строгие поддомены под prune-записью из менее приоритетного источника.
func oracle(srcs []testSource, query string) Action {
	type ent struct {
		domain string
		mode   MatchMode
		action Action
		src    int
		prune  bool
	}
	var ents []ent
	for si, s := range srcs {
		for _, e := range s.entries {
			ents = append(ents, ent{e.domain, testMode(e.subdomains), s.action, si, s.prune})
		}
	}

	applies := func(e ent) bool {
		return e.domain == query || (e.mode == MatchPrefix && strings.HasSuffix(query, "."+e.domain))
	}
	pruned := func(e ent) bool {
		for _, p := range ents {
			if p.prune && p.src > e.src && strings.HasSuffix(e.domain, "."+p.domain) {
				return true
			}
		}
		return false
	}

	best := -1
	for i, e := range ents {
		if pruned(e) || !applies(e) {
			continue
		}
		if best < 0 || len(e.domain) > len(ents[best].domain) ||
			(len(e.domain) == len(ents[best].domain) && e.src > ents[best].src) {
			best = i
		}
	}
	if best < 0 {
		return ActionPass
	}
	return ents[best].action
}

func TestMergeResolve(t *testing.T) {
	srcs := []testSource{
		{action: ActionRemap, entries: []testEntry{
			{"example.com", true},
			{"exact.com", false},
			{"foo.bar", true},
			{"dup.com", true},
			{"deep.pruned.foo.bar", true},
			{"blockade.com", true},
		}},
		{action: ActionBlackhole, entries: []testEntry{
			{"dup.com", true},
		}},
		{action: ActionPass, prune: true, entries: []testEntry{
			{"pruned.foo.bar", true},
			{"block.com", true},
		}},
	}

	cases := map[string]Action{
		"example.com":           ActionRemap,
		"a.b.example.com":       ActionRemap,
		"exact.com":             ActionRemap,
		"sub.exact.com":         ActionPass,      // exact-режим не покрывает поддомены
		"dup.com":               ActionBlackhole, // last-wins: источник 1 поверх 0
		"x.dup.com":             ActionBlackhole,
		"foo.bar":               ActionRemap,
		"other.foo.bar":         ActionRemap,
		"pruned.foo.bar":        ActionPass,
		"deep.pruned.foo.bar":   ActionPass, // prune убрал remap, остаётся passthrough-предок
		"x.deep.pruned.foo.bar": ActionPass,
		"block.com":             ActionPass,
		"sub.block.com":         ActionPass,
		"blockade.com":          ActionRemap, // НЕ под prune block.com — граница не по метке
		"absent.org":            ActionPass,
	}

	mrx, _, err := BuildRadix(runSources(srcs))
	require.NoError(t, err)
	mfst, _, _, err := BuildFST(runSources(srcs))
	require.NoError(t, err)

	for q, want := range cases {
		t.Run(q, func(t *testing.T) {
			require.Equal(t, want, oracle(srcs, q), "oracle (спека)")
			require.Equal(t, want, mrx.Lookup(q), "merge-radix")
			require.Equal(t, want, mfst.Lookup(q), "merge-fst")
		})
	}
}
