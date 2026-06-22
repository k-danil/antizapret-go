package matcher

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// FST обязан давать те же вердикты, что radix: longest-suffix, exact vs prefix,
// поглощение специфичными, prune-карв-аут, отсутствующие → passthrough.
func TestFSTMatchesRadix(t *testing.T) {
	rx := NewRadix[Action]()
	rx.Insert("example.com", ActionRemap, MatchPrefix)
	rx.Insert("foo.bar", ActionRemap, MatchPrefix)
	rx.Insert("m.exact.net", ActionRemap, MatchPrefix)
	rx.Insert("exact.net", ActionRemap, MatchExact)
	rx.Insert("ads.example.com", ActionBlackhole, MatchPrefix)
	rx.Insert("tracker.net", ActionBlackhole, MatchPrefix)
	rx.Insert("safe.example.com", ActionPass, MatchPrefix)
	rx.Insert("pruned.foo.bar", ActionPass, MatchPrefix) // passthrough поверх remap foo.bar
	rx.PruneBelow("pruned.foo.bar")

	rxM := NewRadixMatcher(rx)
	fstM, err := NewFSTMatcher(rx)
	require.NoError(t, err)

	queries := []string{
		"example.com", "a.example.com", "a.b.example.com",
		"safe.example.com", "x.safe.example.com",
		"ads.example.com", "sub.ads.example.com",
		"exact.net", "a.exact.net",
		"m.exact.net", "x.m.exact.net",
		"tracker.net", "x.tracker.net",
		"foo.bar", "deep.foo.bar", "pruned.foo.bar", "x.pruned.foo.bar",
		"random.org", "nothing.test",
	}
	for _, q := range queries {
		require.Equalf(t, rxM.Lookup(q), fstM.Lookup(q), "домен %q", q)
	}
}
