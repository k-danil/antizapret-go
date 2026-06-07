package utils

import "testing"

func TestRadixPruneBelow(t *testing.T) {
	r := NewRadix[int]()
	r.Insert("www.example.com", 1, MatchPrefix)
	r.Insert("a.example.com", 2, MatchPrefix)
	r.Insert("example.com", 9, MatchPrefix)
	r.Insert("other.com", 5, MatchPrefix)

	r.PruneBelow("example.com")

	// всё под example.com теперь ловит сам example.com (специфичные узлы обрезаны)
	for _, q := range []string{"www.example.com", "a.example.com", "deep.www.example.com", "example.com"} {
		if v, ok := r.Get(q); !ok || v != 9 {
			t.Fatalf("Get(%q) = %d,%v want 9", q, v, ok)
		}
	}

	// соседнее поддерево не затронуто
	if v, ok := r.Get("x.other.com"); !ok || v != 5 {
		t.Fatalf("Get(x.other.com) = %d,%v want 5", v, ok)
	}
}
