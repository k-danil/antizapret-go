package server

import (
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
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

// filterAnswer — статический фильтр: AAAA вырезаем (IPv4-only), из HTTPS/SVCB режем
// параметры обхода. Идемпотентен → применяем ОДИН раз до кэша, а не на каждую выдачу.
// Чистит и glue в Extra (MX/NS/SRV), и смешанные ответы, мимо которых qtype-замыкание
// хендлера проходит.
func filterAnswer(in []dns.RR) []dns.RR {
	if !hasStripType(in) {
		return in // нечего вырезать — без копии
	}
	out := make([]dns.RR, 0, len(in))
	for _, rr := range in {
		switch v := rr.(type) {
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
	return out
}

// remapAnswer подменяет A → fake-IP (remap/blackhole). Stateful (маппинг + DNAT c TTL),
// поэтому НЕ кэшируется, а гоняется на каждую выдачу: Map() держит маппинг живым и
// пересоздаёт истёкший. AAAA/SvcParams уже срезаны filterAnswer до кэша — здесь только A.
func remapAnswer(in []dns.RR, transform Transformer) (out []dns.RR, attempted, failed int) {
	out = make([]dns.RR, 0, len(in))
	for _, rr := range in {
		a, ok := rr.(*dns.A)
		if !ok {
			out = append(out, rr)
			continue
		}
		attempted++
		na, err := transform(a)
		if err != nil {
			// best-effort: незамапленную A пропускаем, остальные отдаём — иначе
			// уже созданные для этого ответа маппинги осели бы в ядре впустую
			failed++
			continue
		}
		if na != nil {
			out = append(out, na)
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
