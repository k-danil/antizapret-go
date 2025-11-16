package resolver

import (
	"context"
	"errors"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/cfg"
)

type Resolver struct {
	upstreams []Upstream
}

func NewResolver(config []cfg.Upstream) (r *Resolver, err error) {
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
			err = errors.New("unsupported protocol")
			return
		}

		r.upstreams = append(r.upstreams, upstream)
	}

	if len(r.upstreams) == 0 {
		err = errors.New("no upstreams")
	}

	return
}

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	now := time.Now()
	index := now.Nanosecond() % len(r.upstreams)
	return r.upstreams[index].Resolve(ctx, req)
}

func (r *Resolver) Close() (err error) {
	var errs []error
	for _, u := range r.upstreams {
		err = u.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		err = errors.Join(errs...)
	}

	return
}
