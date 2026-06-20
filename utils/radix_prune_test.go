package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRadixPruneBelow(t *testing.T) {
	r := NewRadix[int]()
	r.Insert("www.example.com", 1, MatchPrefix)
	r.Insert("a.example.com", 2, MatchPrefix)
	r.Insert("example.com", 9, MatchPrefix)
	r.Insert("other.com", 5, MatchPrefix)

	r.PruneBelow("example.com")

	// всё под example.com теперь ловит сам example.com (специфичные узлы обрезаны)
	for _, q := range []string{"www.example.com", "a.example.com", "deep.www.example.com", "example.com"} {
		v, ok := r.Get(q)
		require.Truef(t, ok, "Get(%q) ok", q)
		require.Equalf(t, 9, v, "Get(%q)", q)
	}

	// соседнее поддерево не затронуто
	v, ok := r.Get("x.other.com")
	require.True(t, ok)
	require.Equal(t, 5, v, "Get(x.other.com)")
}
