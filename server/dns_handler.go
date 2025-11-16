package server

import (
	"context"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/log"
	rtr "github.com/antizapret-vpn/go-proxy/server/router"
	"github.com/antizapret-vpn/go-proxy/utils"
)

var blackholeIP = net.IPv4(127, 6, 6, 6)

type Transformer func(*dns.A) (*dns.A, error)

func (s *Server) DNSHandler(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if len(r.Question) != 1 {
		r.Rcode = dns.RcodeFormatError
		_, _ = r.WriteTo(w)
		return
	}

	resp := s.cache.GetResponseLambda(r, func() (resp *dns.Msg, ttl time.Duration, err error) {
		resp, err = s.resolver.Resolve(ctx, r)
		if err != nil || resp == nil {
			if err != nil {
				log.L.Warnw("resolve failed", "err", err)
			}
			r.Rcode = dns.RcodeServerFailure
			resp = r
			return
		}

		if resp.Rcode == dns.RcodeNameError {
			ttl = 24 * time.Hour
		}

		return
	})

	if resp.Rcode != dns.RcodeSuccess {
		_, _ = resp.WriteTo(w)
		return
	}

	var err error
	var mapper Transformer
	switch s.router.Lookup(utils.NormalizeDomain(r.Question[0].Header().Name)) {
	case rtr.ActionPass:
	case rtr.ActionBlackhole:
		mapper = func(a *dns.A) (*dns.A, error) {
			return &dns.A{Hdr: a.Hdr, A: blackholeIP}, nil
		}
	case rtr.ActionRemap:
		ttl := uint32(s.ipMapper.GetTTL().Seconds() * 0.8)
		mapper = func(a *dns.A) (*dns.A, error) {
			fake, mapErr := s.ipMapper.Map(a.A, a.Hdr.Name)
			if mapErr != nil {
				return nil, mapErr
			}
			hdr := a.Hdr
			hdr.TTL = ttl
			return &dns.A{Hdr: hdr, A: fake}, nil
		}
	}

	if mapper != nil {
		resp.Answer, err = s.rewriteRRS(resp.Answer, mapper)
		if err != nil {
			log.L.Warnw("rewrite response failed", "err", err)
			resp.Rcode = dns.RcodeServerFailure
		}
		resp.Extra, err = s.rewriteRRS(resp.Extra, mapper)
		if err != nil {
			log.L.Warnw("rewrite response failed", "err", err)
			resp.Rcode = dns.RcodeServerFailure
		}
	}

	_, _ = resp.WriteTo(w)
}

func (s *Server) rewriteRRS(in []dns.RR, transform Transformer) ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		switch v := rr.(type) {
		case *dns.A:
			na, err := transform(v)
			if err != nil {
				return nil, err
			}
			if na != nil {
				out = append(out, na)
			}
		case *dns.AAAA:
			if !s.ipv6 {
				continue
			}
			out = append(out, v)
		default:
			out = append(out, rr)
		}
	}
	return out, nil
}
