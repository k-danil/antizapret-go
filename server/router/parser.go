package router

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/antizapret-vpn/go-proxy/cfg"
)

type Entry struct {
	Domain     string
	Subdomains bool
}

type Parser interface {
	Parse(r io.Reader, emit func(Entry)) error
}

func newParser(m cfg.Matcher, subdomains bool) (p Parser, err error) {
	switch m.Format {
	case "", cfg.FormatPlain:
		p = PlainParser{subdomains: subdomains}
	case cfg.FormatRegexp:
		if m.Regexp == nil {
			err = fmt.Errorf("source `%s`: format `regexp` requires `regexp` section", m.Name)
			return
		}
		var from *regexp.Regexp
		if from, err = regexp.Compile(m.Regexp.From); err != nil {
			err = fmt.Errorf("source `%s`: invalid regexp: %w", m.Name, err)
			return
		}
		p = RegexpParser{from: from, to: m.Regexp.To, subdomains: subdomains}
	default:
		err = fmt.Errorf("source `%s`: unknown format `%s`", m.Name, m.Format)
	}
	return
}

type PlainParser struct {
	subdomains bool
}

func (p PlainParser) Parse(r io.Reader, emit func(Entry)) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		emit(Entry{Domain: line, Subdomains: p.subdomains})
	}
	return scanner.Err()
}

// RegexpParser — escape-hatch для форматов, не покрытых нативными парсерами.
type RegexpParser struct {
	from       *regexp.Regexp
	to         string
	subdomains bool
}

func (p RegexpParser) Parse(r io.Reader, emit func(Entry)) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !p.from.MatchString(line) {
			continue
		}
		emit(Entry{Domain: p.from.ReplaceAllString(line, p.to), Subdomains: p.subdomains})
	}
	return scanner.Err()
}
