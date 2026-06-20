package server

import (
	"context"
	"net"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/k-danil/antizapret-go/log"
	rtr "github.com/k-danil/antizapret-go/server/router"
	"github.com/k-danil/antizapret-go/utils"
)

var blackholeAddr = netip.AddrFrom4([4]byte{127, 6, 6, 6})

type Transformer func(*dns.A) (*dns.A, error)

func blackholeTransform(a *dns.A) (*dns.A, error) {
	rr := &dns.A{Hdr: a.Hdr}
	rr.Addr = blackholeAddr
	return rr, nil
}

func (s *Server) DNSHandler(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		r.Response = true
		r.Rcode = dns.RcodeFormatError
		r.Data = nil
		_, _ = r.WriteTo(w)
		return
	}

	q := r.Question[0]
	domain := utils.NormalizeDomain(q.Header().Name)
	action := s.router.Lookup(domain)

	// Для remap/blackhole-доменов глушим HTTPS/SVCB: их подсказки (ipv4hint, ECH)
	// позволили бы клиенту пойти мимо подмены A-записи. Пустой NODATA заставляет
	// клиента упасть на A-запрос, который будет подменён.
	if action == rtr.ActionRemap || action == rtr.ActionBlackhole {
		if qtype := dns.RRToType(q); qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB {
			r.Response = true
			r.Rcode = dns.RcodeSuccess
			r.Answer, r.Ns, r.Extra = nil, nil, nil
			r.Data = nil // Data ещё держит байты запроса; обнуляем, чтобы WriteTo перепаковал из полей
			_, _ = r.WriteTo(w)
			return
		}
	}

	resp := s.cache.GetResponseLambda(r, domain, func() (resp *dns.Msg, ttl time.Duration, err error) {
		// резолв под Background: single-flight шарит его на всех ждущих — отмена одного не должна рвать остальных
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		resp, err = s.resolver.Resolve(ctx, r)
		if err != nil || resp == nil {
			if err != nil {
				log.L.Warnw("resolve failed", "err", err)
			}
			resp = nil // не отдаём запрос как ответ — single-flight расшарил бы его на всех ждущих
			return
		}
		return
	})

	if resp == nil {
		r.Response = true
		r.Rcode = dns.RcodeServerFailure
		r.Data = nil
		_, _ = r.WriteTo(w)
		return
	}

	if resp.Rcode != dns.RcodeSuccess {
		resp.Response = true
		resp.Data = nil
		_, _ = resp.WriteTo(w)
		return
	}

	var mapper Transformer
	switch action {
	case rtr.ActionPass:
	case rtr.ActionBlackhole:
		mapper = blackholeTransform
	case rtr.ActionRemap:
		ttl := uint32(s.ipMapper.GetTTL().Seconds() * 0.8)
		mapper = func(a *dns.A) (*dns.A, error) {
			fakeIP, mapErr := s.ipMapper.Map(net.IP(a.Addr.AsSlice()))
			if mapErr != nil {
				return nil, mapErr
			}
			hdr := a.Hdr
			hdr.TTL = ttl
			rr := &dns.A{Hdr: hdr}
			rr.Addr, _ = netip.AddrFromSlice(fakeIP.To4())
			return rr, nil
		}
	}

	if mapper != nil {
		var aAtt, aFail, eAtt, eFail int
		resp.Answer, aAtt, aFail = s.rewriteRRS(resp.Answer, mapper)
		resp.Extra, eAtt, eFail = s.rewriteRRS(resp.Extra, mapper)

		// SERVFAIL только если ни одна A не замапилась (исчерпание пула / сбой firewall):
		// иначе отдаём частичный ответ, а не пустой NODATA.
		if att := aAtt + eAtt; att > 0 && aFail+eFail == att {
			log.L.Warnw("remap failed for all A records", "domain", domain)
			resp.Rcode = dns.RcodeServerFailure
			resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
			resp.Data = nil
		}
	}

	_, _ = resp.WriteTo(w)
}

func (s *Server) rewriteRRS(in []dns.RR, transform Transformer) (out []dns.RR, attempted, failed int) {
	out = make([]dns.RR, 0, len(in))
	for _, rr := range in {
		switch v := rr.(type) {
		case *dns.A:
			attempted++
			na, err := transform(v)
			if err != nil {
				// best-effort: незамапленную A пропускаем, остальные отдаём — иначе
				// уже созданные для этого ответа маппинги осели бы в ядре впустую
				failed++
				continue
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
	return
}
