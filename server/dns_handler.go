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
		r.Response = true
		r.Rcode = dns.RcodeFormatError
		r.Data = nil
		_, _ = r.WriteTo(w)
		return
	}

	action := s.router.Lookup(utils.NormalizeDomain(r.Question[0].Header().Name))

	// Для remap/blackhole-доменов глушим HTTPS/SVCB: их подсказки (ipv4hint, ECH)
	// позволили бы клиенту пойти мимо подмены A-записи. Пустой NODATA заставляет
	// клиента упасть на A-запрос, который будет подменён.
	if action == rtr.ActionRemap || action == rtr.ActionBlackhole {
		if qtype := dns.RRToType(r.Question[0]); qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB {
			r.Response = true
			r.Rcode = dns.RcodeSuccess
			r.Answer, r.Ns, r.Extra = nil, nil, nil
			r.Data = nil // Data ещё держит байты запроса; обнуляем, чтобы WriteTo перепаковал из полей
			_, _ = r.WriteTo(w)
			return
		}
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
		resp.Response = true
		resp.Data = nil
		_, _ = resp.WriteTo(w)
		return
	}

	var err error
	var mapper Transformer
	switch action {
	case rtr.ActionPass:
	case rtr.ActionBlackhole:
		mapper = func(a *dns.A) (*dns.A, error) {
			return &dns.A{Hdr: a.Hdr, A: blackholeIP}, nil
		}
	case rtr.ActionRemap:
		ttl := uint32(s.ipMapper.GetTTL().Seconds() * 0.8)
		mapper = func(a *dns.A) (*dns.A, error) {
			fakeIP, mapErr := s.ipMapper.Map(a.A, a.Hdr.Name)
			if mapErr != nil {
				return nil, mapErr
			}
			hdr := a.Hdr
			hdr.TTL = ttl
			return &dns.A{Hdr: hdr, A: fakeIP}, nil
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
			// remap/blackhole применяются только к A; AAAA убираем, чтобы реальный
			// IPv6 не утёк мимо туннеля — клиент упадёт на IPv4.
			continue
		default:
			out = append(out, rr)
		}
	}
	return out, nil
}
