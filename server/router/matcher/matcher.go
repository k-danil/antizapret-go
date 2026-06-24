package matcher

import (
	"bytes"

	"github.com/blevesearch/vellum"
)

type Matcher interface {
	Lookup(domain string) Action
}

const fstPrefixBit = 1 // младший бит значения FST: запись покрывает поддомены (MatchPrefix)

type radixMatcher struct{ rx *Radix[Action] }

func (m radixMatcher) Lookup(domain string) Action {
	if a, ok := m.rx.Get(domain); ok {
		return a
	}
	return ActionPass
}

type fstMatcher struct{ fst *vellum.FST }

// Lookup воспроизводит longest-suffix-match radix через публичный Get: сначала полный
// ключ (exact|prefix совпадают), затем родительские метки сверху вниз (их покрывает
// только prefix-запись). Значение: action<<1 | prefix-бит.
func (m fstMatcher) Lookup(domain string) Action {
	rev := ReverseLabels(domain)
	if v, ok, err := m.fst.Get(rev); err == nil && ok {
		return Action(v >> 1)
	}
	for i := len(rev) - 1; i >= 0; i-- {
		if rev[i] != '.' {
			continue
		}
		if v, ok, err := m.fst.Get(rev[:i]); err == nil && ok && v&fstPrefixBit != 0 {
			return Action(v >> 1)
		}
	}
	return ActionPass
}

// RunSource: Next выдаёт ключи по возрастанию; позиция в срезе = приоритет
// (при равном ключе побеждает больший индекс, его prune действует на меньшие).
type RunSource struct {
	Next   func() (key []byte, mode MatchMode, ok bool)
	Action Action
	Prune  bool
}

// mergeResolve сливает источники, разрешая last-wins (больший индекс) и prune: запись
// отбрасывается, если её по границе меток покрывает prune-префикс приоритетнее.
func mergeResolve(srcs []RunSource, emit func(key []byte, action Action, mode MatchMode) error) (n int, err error) {
	type cursor struct {
		key  []byte
		mode MatchMode
		ok   bool
	}
	curs := make([]cursor, len(srcs))
	advance := func(i int) {
		k, m, ok := srcs[i].Next()
		curs[i] = cursor{key: k, mode: m, ok: ok}
	}
	for i := range srcs {
		advance(i)
	}

	type frame struct {
		key []byte
		src int
	}
	var prune []frame

	for {
		best := -1
		for i := range curs {
			if curs[i].ok && (best < 0 || bytes.Compare(curs[i].key, curs[best].key) < 0) {
				best = i
			}
		}
		if best < 0 {
			break
		}
		key := curs[best].key

		winner := -1
		for i := range curs {
			if curs[i].ok && bytes.Equal(curs[i].key, key) {
				winner = i
			}
		}
		mode := curs[winner].mode

		for len(prune) > 0 && !bytes.HasPrefix(key, prune[len(prune)-1].key) {
			prune = prune[:len(prune)-1]
		}
		pruned := false
		for _, f := range prune {
			if f.src > winner && labelCovers(f.key, key) {
				pruned = true
				break
			}
		}

		if !pruned {
			if err = emit(key, srcs[winner].Action, mode); err != nil {
				return
			}
			n++
		}
		if srcs[winner].Prune {
			prune = append(prune, frame{key: key, src: winner})
		}

		for i := range curs {
			if curs[i].ok && bytes.Equal(curs[i].key, key) {
				advance(i)
			}
		}
	}
	return
}

func labelCovers(p, k []byte) bool {
	return len(p) < len(k) && bytes.HasPrefix(k, p) && k[len(p)] == '.'
}

func BuildFST(srcs []RunSource) (m Matcher, data []byte, n int, err error) {
	var buf bytes.Buffer
	b, err := vellum.New(&buf, nil)
	if err != nil {
		return
	}
	n, err = mergeResolve(srcs, func(key []byte, action Action, mode MatchMode) error {
		v := uint64(action) << 1
		if mode == MatchPrefix {
			v |= fstPrefixBit
		}
		return b.Insert(key, v)
	})
	if err != nil {
		return
	}
	if err = b.Close(); err != nil {
		return
	}
	data = buf.Bytes()
	m, err = LoadFST(data)
	return
}

func LoadFST(data []byte) (Matcher, error) {
	fst, err := vellum.Load(data)
	if err != nil {
		return nil, err
	}
	return fstMatcher{fst}, nil
}

func BuildRadix(srcs []RunSource) (m Matcher, n int, err error) {
	rx := NewRadix[Action]()
	n, err = mergeResolve(srcs, func(key []byte, action Action, mode MatchMode) error {
		rx.InsertReversed(key, action, mode)
		return nil
	})
	if err != nil {
		return
	}
	m = radixMatcher{rx}
	return
}
