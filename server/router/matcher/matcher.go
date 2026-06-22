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

func NewRadixMatcher(rx *Radix[Action]) Matcher { return radixMatcher{rx} }

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

func NewFSTMatcher(rx *Radix[Action]) (Matcher, error) {
	fst, err := fstFromRadix(rx)
	if err != nil {
		return nil, err
	}
	return fstMatcher{fst}, nil
}

func fstFromRadix(rx *Radix[Action]) (*vellum.FST, error) {
	var buf bytes.Buffer
	b, err := vellum.New(&buf, nil)
	if err != nil {
		return nil, err
	}
	// Walk отдаёт ключи лексикографически — ровно порядок, требуемый vellum.Insert.
	var insErr error
	rx.Walk(func(rev []byte, mode MatchMode, val Action) {
		if insErr != nil {
			return
		}
		v := uint64(val) << 1
		if mode == MatchPrefix {
			v |= fstPrefixBit
		}
		insErr = b.Insert(append([]byte(nil), rev...), v)
	})
	if insErr != nil {
		return nil, insErr
	}
	if err = b.Close(); err != nil {
		return nil, err
	}
	return vellum.Load(buf.Bytes())
}
