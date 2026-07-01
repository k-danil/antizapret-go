package server

import (
	"context"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/metrics"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/utils"
)

func (s *Server) DNSHandler(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	served, rcode, action := metrics.ServedCache, metrics.RcodeServFail, metrics.ActionNone
	if s.metrics.Enabled() {
		defer func(now time.Time) {
			s.metrics.ObserveRequest(rcode, action, served, time.Since(now))
		}(time.Now())
	}

	if len(r.Question) != 1 {
		rcode, served = metrics.RcodeFormErr, metrics.ServedError
		r.Response = true
		r.Rcode = dns.RcodeFormatError
		reuseAndWrite(w, r)
		return
	}

	q := r.Question[0]
	qtype := dns.RRToType(q)
	domain := utils.NormalizeDomain(q.Header().Name)
	act := s.router.Lookup(domain)
	action = act.String()

	if act == matcher.ActionNXDomain {
		rcode, served = metrics.RcodeNXDomain, metrics.ServedSuppressed
		r.Response = true
		r.Rcode = dns.RcodeNameError
		r.Answer, r.Extra = nil, nil
		r.Ns = negativeAuthority(q.Header().Name)
		reuseAndWrite(w, r)
		return
	}

	// AAAA → NODATA: гоним всех на IPv4, реальный IPv6 ушёл бы мимо туннеля.
	if qtype == dns.TypeAAAA || isDDRName(domain) {
		rcode, served = metrics.RcodeNoError, metrics.ServedSuppressed
		r.Response = true
		r.Rcode = dns.RcodeSuccess
		r.Answer, r.Extra = nil, nil
		r.Ns = negativeAuthority(q.Header().Name)
		reuseAndWrite(w, r)
		return
	}

	resp, hit := s.cache.GetResponseLambda(r, domain, func() (resp *dns.Msg, ttl time.Duration, err error) {
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
		// статический фильтр — ОДИН раз до кэша (идемпотентен); ремап stateful, в хендлере
		resp.Answer = filterAnswer(resp.Answer)
		resp.Extra = filterAnswer(resp.Extra)
		resp.Data = nil // поля изменились — WriteTo должен перепаковать, а не отдать сырой Data
		return
	})
	if !hit {
		served = metrics.ServedUpstream
	}

	if resp == nil {
		r.Response = true
		r.Rcode = dns.RcodeServerFailure
		reuseAndWrite(w, r)
		return
	}

	if resp.Rcode != dns.RcodeSuccess {
		rcode = rcodeLabel(resp.Rcode)
		resp.Response = true
		resp.Data = nil
		_, _ = resp.WriteTo(w)
		return
	}

	var mapper Transformer
	switch act {
	case matcher.ActionPass:
	case matcher.ActionBlackhole:
		mapper = blackholeTransform
	case matcher.ActionRemap:
		ttl := uint32(s.ipMapper.GetTTL().Seconds() * 0.8)
		mapper = func(a *dns.A) (*dns.A, error) {
			fakeIP, mapErr := s.ipMapper.Map(a.Addr.AsSlice())
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
		resp.Answer, aAtt, aFail = remapAnswer(resp.Answer, mapper)
		resp.Extra, eAtt, eFail = remapAnswer(resp.Extra, mapper)

		// SERVFAIL только если ни одна A не замапилась (исчерпание пула / сбой firewall):
		// иначе отдаём частичный ответ, а не пустой NODATA.
		if att := aAtt + eAtt; att > 0 && aFail+eFail == att {
			log.L.Warnw("remap failed for all A records", "domain", domain)
			resp.Rcode = dns.RcodeServerFailure
			resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
			resp.Data = nil
		}
	}

	rcode = rcodeLabel(resp.Rcode)
	_, _ = resp.WriteTo(w)
}

// m.Data[:0] (не nil!) переиспользует буфер запроса из srv.MsgPool: с nil Pack аллоцирует
// мелкий буфер, WriteTo вернёт его в пул, и следующий recvmmsg-приём упадёт на r.Data[:N]
// (Put форка не отбрасывает cap < size).
func reuseAndWrite(w dns.ResponseWriter, m *dns.Msg) {
	m.Data = m.Data[:0]
	_, _ = m.WriteTo(w)
}

func rcodeLabel(rcode uint16) string {
	switch rcode {
	case dns.RcodeSuccess:
		return metrics.RcodeNoError
	case dns.RcodeFormatError:
		return metrics.RcodeFormErr
	case dns.RcodeServerFailure:
		return metrics.RcodeServFail
	case dns.RcodeNameError:
		return metrics.RcodeNXDomain
	case dns.RcodeNotImplemented:
		return metrics.RcodeNotImp
	case dns.RcodeRefused:
		return metrics.RcodeRefused
	default:
		return metrics.RcodeOther
	}
}
