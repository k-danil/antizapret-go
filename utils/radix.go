package utils

import (
	"bytes"
	"cmp"
	"slices"
	"sync"
)

type MatchMode uint8

const (
	MatchNone MatchMode = iota
	MatchExact
	MatchPrefix
)

type child[T any] struct {
	key  byte
	node *radixNode[T]
}

type radixNode[T any] struct {
	prefix   []byte
	children []child[T]
	match    MatchMode
	value    T
}

type Radix[T any] struct {
	root *radixNode[T]
	pool sync.Pool
}

func NewRadix[T any]() *Radix[T] {
	return &Radix[T]{
		root: &radixNode[T]{},
		pool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 64))
			},
		},
	}
}

func (n *radixNode[T]) insertChildAt(i int, k byte, ch *radixNode[T]) {
	n.children = append(n.children, child[T]{})
	copy(n.children[i+1:], n.children[i:])
	n.children[i] = child[T]{key: k, node: ch}
}

func (r *Radix[T]) Insert(key string, val T, mode MatchMode) {
	if key == "" {
		return
	}

	r.root.insert(reverseLabels(key), val, mode)
}

func (n *radixNode[T]) insert(s []byte, val T, mode MatchMode) {
	if len(s) == 0 {
		n.value = val
		n.match = mode
		return
	}
	c := s[0]

	i, ok := slices.BinarySearchFunc(n.children, c, func(c child[T], u uint8) int {
		return cmp.Compare(c.key, u)
	})
	if !ok {
		n.insertChildAt(i, c, &radixNode[T]{
			prefix: s,
			value:  val,
			match:  mode,
		})
		return
	}
	ch := n.children[i].node
	cl := commonPrefixLen(ch.prefix, s)
	switch {
	case cl == len(ch.prefix):
		ch.insert(s[cl:], val, mode)
	case cl < len(ch.prefix) && cl < len(s):
		split := &radixNode[T]{
			prefix:   ch.prefix[cl:],
			children: ch.children,
			match:    ch.match,
			value:    ch.value,
		}
		ch.prefix = ch.prefix[:cl]
		ch.children = []child[T]{
			{key: split.prefix[0], node: split},
		}
		var zero T
		ch.value = zero
		ch.match = MatchNone
		ch.insert(s[cl:], val, mode)
	case cl == len(s):
		rest := ch.prefix[cl:]
		if len(rest) == 0 {
			ch.value = val
			ch.match = mode
			return
		}
		newChild := &radixNode[T]{
			prefix:   rest,
			children: ch.children,
			match:    ch.match,
			value:    ch.value,
		}
		ch.prefix = ch.prefix[:cl]
		ch.children = []child[T]{
			{key: newChild.prefix[0], node: newChild},
		}
		ch.value = val
		ch.match = mode
	}
}

func commonPrefixLen(a, b []byte) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func (r *Radix[T]) Get(key string) (T, bool) {
	var zero T
	if key == "" {
		return zero, false
	}

	b := r.pool.Get().(*bytes.Buffer)
	defer r.pool.Put(b)
	b.Reset()
	reverseLabelsInto(b, key)

	return r.root.get(b.Bytes(), zero, false)
}

func (n *radixNode[T]) get(s []byte, bestVal T, bestOk bool) (T, bool) {
	if len(s) == 0 {
		if n.match == MatchExact {
			return n.value, true
		}
		return bestVal, bestOk
	}

	c := s[0]
	var i int
	var ok bool
	if len(n.children) < 8 {
		for i = 0; i < len(n.children); i++ {
			if n.children[i].key == c {
				ok = true
				break
			}
		}
	} else {
		i, ok = slices.BinarySearchFunc(n.children, c, func(c child[T], u uint8) int {
			return cmp.Compare(c.key, u)
		})
	}

	if !ok {
		return bestVal, bestOk
	}

	ch := n.children[i].node
	p := ch.prefix

	if len(s) >= len(p) && bytes.HasPrefix(s, p) {
		if ch.match == MatchPrefix {
			if len(s) == len(p) || s[len(p)] == '.' {
				bestVal, bestOk = ch.value, true
			}
		}
		if len(s) == len(p) {
			if ch.match == MatchExact {
				return ch.value, true
			}
			return bestVal, bestOk
		}
		return ch.get(s[len(p):], bestVal, bestOk)
	}

	return bestVal, bestOk
}

// PruneBelow обрезает все более специфичные ветки под key (узел key сохраняется).
// Вызывать после Insert(key, ...): тогда узел key гарантированно существует.
func (r *Radix[T]) PruneBelow(key string) {
	if key == "" {
		return
	}
	r.root.pruneBelow(reverseLabels(key))
}

func (n *radixNode[T]) pruneBelow(s []byte) {
	if len(s) == 0 {
		n.children = nil
		return
	}

	i, ok := slices.BinarySearchFunc(n.children, s[0], func(c child[T], u uint8) int {
		return cmp.Compare(c.key, u)
	})
	if !ok {
		return
	}

	ch := n.children[i].node
	if len(s) < len(ch.prefix) || !bytes.HasPrefix(s, ch.prefix) {
		return
	}
	if len(s) == len(ch.prefix) {
		ch.children = nil
		return
	}
	ch.pruneBelow(s[len(ch.prefix):])
}

func reverseLabelsInto(b *bytes.Buffer, key string) {
	end := len(key)
	for end >= 0 {
		i := end - 1
		for i >= 0 && key[i] != '.' {
			i--
		}
		if i+1 < end {
			b.WriteString(key[i+1 : end])
			if i > 0 {
				b.WriteByte('.')
			}
		}
		end = i
	}
}

// reverseLabels возвращает владеемую копию — Insert/PruneBelow сохраняют её как prefix узлов.
func reverseLabels(key string) []byte {
	var b bytes.Buffer
	b.Grow(len(key))
	reverseLabelsInto(&b, key)
	return b.Bytes()
}
