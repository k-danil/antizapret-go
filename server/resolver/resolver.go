package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/metrics"
)

type Resolver struct {
	upstreams []Upstream
	next      atomic.Uint64
}

func upstreamLabel(u cfg.Upstream) string {
	if u.Name != "" {
		return u.Name
	}
	return u.DSN
}

type instrumentedUpstream struct {
	Upstream
	m    *metrics.Metrics
	name string
}

func (i instrumentedUpstream) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	defer func(now time.Time) {
		i.m.ObserveUpstream(i.name, err, time.Since(now))
	}(time.Now())

	resp, err = i.Upstream.Resolve(ctx, req)
	return
}

func NewResolver(config []cfg.Upstream, m *metrics.Metrics) (r *Resolver, err error) {
	r = &Resolver{
		upstreams: make([]Upstream, 0, len(config)),
	}

	for _, u := range config {
		var upstream Upstream
		switch {
		case strings.HasPrefix(u.DSN, `tcp`), strings.HasPrefix(u.DSN, `udp`):
			if upstream, err = NewClassicUpstream(u.Name, u.DSN, u.Timeout); err != nil {
				return
			}
		case strings.HasPrefix(u.DSN, `http`), strings.HasPrefix(u.DSN, `https`):
			if upstream, err = NewDoHUpstream(u.Name, u.DSN, u.Timeout); err != nil {
				return
			}
		default:
			err = fmt.Errorf("unsupported protocol `%s` for upstream `%s`", u.DSN, u.Name)
			return
		}

		if m.Enabled() {
			upstream = instrumentedUpstream{Upstream: upstream, m: m, name: upstreamLabel(u)}
		}
		r.upstreams = append(r.upstreams, upstream)
	}

	if len(r.upstreams) == 0 {
		err = errors.New("no upstreams")
	}

	return
}

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if len(r.upstreams) == 0 {
		err = errors.New("no upstreams")
		return
	}
	n := len(r.upstreams)
	start := int(r.next.Add(1) % uint64(n))

	var errs []error
	for i := range n {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		if resp, err = r.upstreams[(start+i)%n].Resolve(ctx, req); err == nil {
			return
		}
		errs = append(errs, err)
	}

	err = errors.Join(errs...)
	return
}
