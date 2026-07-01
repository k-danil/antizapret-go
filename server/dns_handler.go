package server

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/metrics"
	"github.com/k-danil/antizapret-go/server/router/matcher"
	"github.com/k-danil/antizapret-go/utils"
)

var blackholeAddr = netip.AddrFrom4([4]byte{127, 6, 6, 6})

// Синтетический SOA в authority негативного ответа (NXDOMAIN/NODATA): без него
// (RFC 2308) резолверы не кэшируют негатив и переспрашивают на каждый запрос.
// Длительность негативного кэша задают только TTL записи и Minttl; прочие таймеры инертны.
const (
	soaNegTTL     uint32 = 3600
	soaSerial     uint32 = 1
	soaRefresh    uint32 = 3600
	soaRetry      uint32 = 600
	soaExpire     uint32 = 86400
	soaMboxPrefix        = "hostmaster."
)

func negativeAuthority(name string) []dns.RR {
	soa := &dns.SOA{Hdr: dns.Header{Name: name, TTL: soaNegTTL, Class: dns.ClassINET}}
	soa.Ns = name
	soa.Mbox = soaMboxPrefix + name
	soa.Serial = soaSerial
	soa.Refresh = soaRefresh
	soa.Retry = soaRetry
	soa.Expire = soaExpire
	soa.Minttl = soaNegTTL
	return []dns.RR{soa}
}

// `_*.arpa` — семейство DDR-имён (`_dns.resolver.arpa`, RFC 9462), через которые
// клиент находит зашифрованный резолвер сети. Underscore-метка отсекает обычный
// reverse-DNS (`…in-addr.arpa`, `home.arpa`), который трогать нельзя.
func isDDRName(domain string) bool {
	return strings.HasSuffix(domain, ".arpa") && strings.Contains(domain, "_")
}

type Transformer func(*dns.A) (*dns.A, error)

func blackholeTransform(a *dns.A) (*dns.A, error) {
	rr := &dns.A{Hdr: a.Hdr}
	rr.Addr = blackholeAddr
	return rr, nil
}

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

	// rewriteRRS — на ЛЮБОМ ответе: AAAA и SvcParams чистим и из glue в Extra (MX/NS/SRV),
	// и из смешанных ответов, мимо которых qtype-замыкание проходит.
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

func (s *Server) rewriteRRS(in []dns.RR, transform Transformer) (out []dns.RR, attempted, failed int) {
	if transform == nil && !hasStripType(in) {
		return in, 0, 0 // нечего вырезать — без копии
	}
	out = make([]dns.RR, 0, len(in))
	for _, rr := range in {
		switch v := rr.(type) {
		case *dns.A:
			if transform == nil {
				out = append(out, rr)
				continue
			}
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
			continue
		case *dns.HTTPS:
			if filtered, changed := stripSvcParams(v.Value); changed {
				c := *v
				c.Value = filtered
				out = append(out, &c)
			} else {
				out = append(out, v)
			}
		case *dns.SVCB:
			if filtered, changed := stripSvcParams(v.Value); changed {
				c := *v
				c.Value = filtered
				out = append(out, &c)
			} else {
				out = append(out, v)
			}
		default:
			out = append(out, rr)
		}
	}
	return
}

func isStrippedParam(p svcb.Pair) bool {
	switch p.(type) {
	case *svcb.IPV4HINT, *svcb.IPV6HINT, *svcb.DOHPATH:
		return true
	}
	return false
}

// stripSvcParams убирает из HTTPS/SVCB параметры обхода: ipv4hint/ipv6hint (реальный IP
// мимо подмены A) и dohpath (анонс DoH-эндпоинта, RFC 9461). alpn/ech и прочее — оставляем.
func stripSvcParams(in []svcb.Pair) (out []svcb.Pair, changed bool) {
	for i, p := range in {
		if !isStrippedParam(p) {
			continue
		}
		out = make([]svcb.Pair, 0, len(in)-1)
		out = append(out, in[:i]...)
		for _, q := range in[i+1:] {
			if !isStrippedParam(q) {
				out = append(out, q)
			}
		}
		return out, true
	}
	return in, false
}

func hasStripType(rrs []dns.RR) bool {
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.AAAA, *dns.HTTPS, *dns.SVCB:
			return true
		}
	}
	return false
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
