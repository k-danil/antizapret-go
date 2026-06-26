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

var blackholeAddr = netip.AddrFrom4([4]byte{127, 6, 6, 6})

// Синтетический SOA в authority NXDOMAIN-ответа: без него (RFC 2308) резолверы не
// кэшируют отрицательный ответ и переспрашивают апстрим на каждый запрос. Длительность
// негативного кэша задают только TTL записи и Minttl; прочие таймеры инертны.
const (
	nxSOANegTTL     uint32 = 3600
	nxSOASerial     uint32 = 1
	nxSOARefresh    uint32 = 3600
	nxSOARetry      uint32 = 600
	nxSOAExpire     uint32 = 86400
	nxSOAMboxPrefix        = "hostmaster."
)

func nxdomainAuthority(name string) []dns.RR {
	soa := &dns.SOA{Hdr: dns.Header{Name: name, TTL: nxSOANegTTL, Class: dns.ClassINET}}
	soa.Ns = name
	soa.Mbox = nxSOAMboxPrefix + name
	soa.Serial = nxSOASerial
	soa.Refresh = nxSOARefresh
	soa.Retry = nxSOARetry
	soa.Expire = nxSOAExpire
	soa.Minttl = nxSOANegTTL
	return []dns.RR{soa}
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
		r.Ns = nxdomainAuthority(q.Header().Name)
		reuseAndWrite(w, r)
		return
	}

	// Для remap/blackhole-доменов глушим HTTPS/SVCB: их подсказки (ipv4hint, ECH)
	// позволили бы клиенту пойти мимо подмены A-записи. Пустой NODATA заставляет
	// клиента упасть на A-запрос, который будет подменён.
	if act == matcher.ActionRemap || act == matcher.ActionBlackhole {
		if qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB {
			rcode, served = metrics.RcodeNoError, metrics.ServedSuppressed
			r.Response = true
			r.Rcode = dns.RcodeSuccess
			r.Answer, r.Ns, r.Extra = nil, nil, nil
			reuseAndWrite(w, r)
			return
		}
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
