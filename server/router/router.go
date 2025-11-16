package router

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/utils"
)

type Router struct {
	sources []Source

	r atomic.Pointer[utils.Radix[Action]]
}

type Regexp struct {
	From regexp.Regexp
	To   string
}

type Source struct {
	Name   string
	Action Action
	URI    string
	Regexp *Regexp
}

func (s *Source) GetReader(ctx context.Context) (r io.ReadCloser, err error) {
	var uri *url.URL
	if uri, err = url.Parse(s.URI); err != nil {
		err = fmt.Errorf("failed to parse uri `%s` source `%s`: %w", s.URI, s.Name, err)
		return
	}

	switch uri.Scheme {
	case "file":
		if r, err = os.Open(uri.Path); err != nil {
			err = fmt.Errorf("failed to open file `%s` for source `%s`: %w", uri.Path, s.Name, err)
			return
		}
	case "http", "https":
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil); err != nil {
			err = fmt.Errorf("failed to create request for source `%s`: %w", s.Name, err)
			return
		}
		var resp *http.Response
		if resp, err = http.DefaultClient.Do(req); err != nil {
			err = fmt.Errorf("failed to get response for source `%s`: %w", s.Name, err)
			return
		}
		r = resp.Body
	default:
		err = fmt.Errorf("unsupported scheme `%s` for source `%s`", uri.Scheme, s.Name)
		return
	}
	return
}

type Action uint8

const (
	ActionBlackhole Action = iota
	ActionRemap
	ActionPass
)

func NewRouter(routers []cfg.Matcher) (r *Router) {
	sources := make([]Source, 0, len(routers))
	for _, rtr := range routers {
		s := Source{
			Name: rtr.Name,
			URI:  rtr.Source,
		}
		if rtr.Regexp != nil {
			s.Regexp = &Regexp{
				From: *regexp.MustCompile(rtr.Regexp.From),
				To:   rtr.Regexp.To,
			}
		}

		switch rtr.Type {
		case cfg.RouterTypeBlackhole:
			s.Action = ActionBlackhole
		case cfg.RouterTypeRemap:
			s.Action = ActionRemap
		case cfg.RouterTypePassthrough:
			s.Action = ActionPass
		}
		sources = append(sources, s)
	}
	r = &Router{
		sources: sources,
	}

	return
}

func (r *Router) Rebuild(ctx context.Context) error {
	radix := utils.NewRadix[Action]()

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var length int
	for _, s := range r.sources {
		err := func(s Source) (err error) {
			var rdr io.ReadCloser
			if rdr, err = s.GetReader(ctx); err != nil {
				err = fmt.Errorf("failed to get reader for source `%s`: %w", s.Name, err)
				return
			}
			defer func() { _ = rdr.Close() }()
			scanner := bufio.NewScanner(rdr)
			for scanner.Scan() {
				line, match := r.processLine(scanner.Text(), s.Regexp)
				if line != "" {
					radix.Insert(line, s.Action, match)
					length++
				} else {
					log.L.Warnw("skipped line in source", "line", scanner.Text(), "source", s.Name)
				}
			}
			err = scanner.Err()
			if err != nil {
				err = fmt.Errorf("failed to read source `%s`: %w", s.Name, err)
			}

			return
		}(s)
		if err != nil {
			return err
		}
	}

	log.L.Infow("router rebuilt", "length", length)
	r.r.Store(radix)

	return nil
}

func (r *Router) Lookup(domain string) (action Action) {
	radix := r.r.Load()
	if radix == nil {
		return ActionPass
	}
	var ok bool
	action, ok = radix.Get(domain)
	if !ok {
		action = ActionPass
	}
	return
}

func (r *Router) processLine(line string, regexp *Regexp) (domain string, match utils.MatchMode) {
	line = utils.DomainToUnicode(line)
	if regexp != nil {
		line = regexp.From.ReplaceAllString(line, regexp.To)
	}
	if strings.HasPrefix(line, `.`) {
		match = utils.MatchPrefix
	} else {
		match = utils.MatchExact
	}
	domain = utils.NormalizeDomain(line)

	return
}
