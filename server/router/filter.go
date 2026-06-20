package router

import (
	"fmt"
	"regexp"

	"github.com/k-danil/antizapret-go/cfg"
)

type Filter struct {
	exclude []*regexp.Regexp
}

func newFilter(m cfg.Matcher) (f *Filter, err error) {
	if m.Filter == nil || len(m.Filter.Exclude) == 0 {
		return
	}

	f = &Filter{exclude: make([]*regexp.Regexp, 0, len(m.Filter.Exclude))}
	for _, pattern := range m.Filter.Exclude {
		var re *regexp.Regexp
		if re, err = regexp.Compile(pattern); err != nil {
			err = fmt.Errorf("source `%s`: invalid exclude pattern `%s`: %w", m.Name, pattern, err)
			return nil, err
		}
		f.exclude = append(f.exclude, re)
	}

	return
}

func (f *Filter) Keep(domain string) bool {
	if f == nil {
		return true
	}
	for _, re := range f.exclude {
		if re.MatchString(domain) {
			return false
		}
	}
	return true
}
