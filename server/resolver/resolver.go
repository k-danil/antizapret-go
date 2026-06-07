package resolver

import (
	"context"
	"errors"
	"fmt"
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
			err = fmt.Errorf("unsupported protocol `%s` for upstream `%s`", u.DSN, u.Name)
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
	if len(r.upstreams) == 0 {
		err = errors.New("no upstreams")
		return
	}
	n := len(r.upstreams)
	start := time.Now().Nanosecond() % n

	var errs []error
	for i := 0; i < n; i++ {
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
