package server

import (
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

var blackholeAddr = netip.AddrFrom4([4]byte{127, 6, 6, 6})

// RFC 2308: без SOA в authority негатив не кэшируется; срок = min(TTL, Minttl), прочие таймеры инертны.
const (
	soaNegTTL     uint32 = 3600
	soaSerial     uint32 = 1
	soaRefresh    uint32 = 3600
	soaRetry      uint32 = 600
	soaExpire     uint32 = 86400
	soaMboxPrefix        = "hostmaster."
)

func negativeAuthority(name string) []dns.RR {
	return []dns.RR{&dns.SOA{
		Hdr:     dns.Header{Name: name, TTL: soaNegTTL, Class: dns.ClassINET},
		Ns:      name,
		Mbox:    soaMboxPrefix + name,
		Serial:  soaSerial,
		Refresh: soaRefresh,
		Retry:   soaRetry,
		Expire:  soaExpire,
		Minttl:  soaNegTTL,
	}}
}

// DDR-имена (RFC 9462) всегда с '_'-меткой — это отсекает обычный reverse-DNS (in-addr.arpa, home.arpa).
func isDDRName(domain string) bool {
	return strings.HasSuffix(domain, ".arpa") && strings.Contains(domain, "_")
}

type Transformer func(*dns.A) (*dns.A, error)

func blackholeTransform(a *dns.A) (*dns.A, error) {
	return &dns.A{Hdr: a.Hdr, Addr: blackholeAddr}, nil
}

// Нужен и при AAAA→NODATA в хендлере: AAAA и hints приходят glue в Extra и в ответах на другие qtype.
func filterAnswer(in []dns.RR) []dns.RR {
	out := in[:0]
	for _, rr := range in {
		switch v := rr.(type) {
		case *dns.AAAA:
			continue
		case *dns.HTTPS:
			v.Value = slices.DeleteFunc(v.Value, isStrippedParam)
		case *dns.SVCB:
			v.Value = slices.DeleteFunc(v.Value, isStrippedParam)
		}
		out = append(out, rr)
	}
	return out
}

// Не кэшировать: Map() на каждой выдаче продлевает маппинг и пересоздаёт истёкший в ядре.
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

// ipv4/ipv6hint протащат реальный IP мимо подмены A, dohpath (RFC 9461) уведёт клиента на DoH мимо нас.
func isStrippedParam(p svcb.Pair) bool {
	switch p.(type) {
	case *svcb.IPV4HINT, *svcb.IPV6HINT, *svcb.DOHPATH:
		return true
	}
	return false
}
