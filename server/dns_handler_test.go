package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/server/cache"
	"github.com/k-danil/antizapret-go/server/resolver"
	rtr "github.com/k-danil/antizapret-go/server/router"
	"github.com/k-danil/antizapret-go/server/router/store"
	"github.com/stretchr/testify/require"
)

type captureWriter struct{ buf []byte }

func (c *captureWriter) Write(b []byte) (int, error) { c.buf = append(c.buf, b...); return len(b), nil }
func (c *captureWriter) Close() error                { return nil }
func (c *captureWriter) LocalAddr() net.Addr         { return nil }
func (c *captureWriter) RemoteAddr() net.Addr        { return nil }
func (c *captureWriter) Conn() net.Conn              { return nil }
func (c *captureWriter) Session() *dns.Session       { return nil }
func (c *captureWriter) Hijack()                     {}

func remapServer(t *testing.T, domain string) *Server {
	t.Helper()
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(listPath, []byte(domain), 0o600))

	st, err := store.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	r, err := rtr.NewRouter([]cfg.Matcher{
		{Name: "s", Type: cfg.RouterTypeRemap, Source: "file://" + listPath, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, st, cfg.MatcherRadix)
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	return &Server{router: r, timeout: time.Second}
}

func typedQuery(name string, rr dns.RR) *dns.Msg {
	rr.Header().Name = name
	rr.Header().Class = dns.ClassINET
	return &dns.Msg{Question: []dns.RR{rr}}
}

func TestDNSHandlerSuppressesAAAAAndDDR(t *testing.T) {
	s := remapServer(t, "blocked.test") // в списке только blocked.test

	cases := []struct {
		name string
		rr   dns.RR
	}{
		{"blocked.test.", &dns.AAAA{}}, // AAAA у всех (в списке и нет) → IPv4-only
		{"unlisted.test.", &dns.AAAA{}},
		{"_dns.resolver.arpa.", &dns.SVCB{}}, // DDR — на любой тип
		{"_dns.resolver.arpa.", &dns.A{}},
	}

	for _, c := range cases {
		w := &captureWriter{}
		s.DNSHandler(context.Background(), w, typedQuery(c.name, c.rr))

		require.GreaterOrEqualf(t, len(w.buf), 2, "%s/%T: ответ записан", c.name, c.rr)
		parsed := &dns.Msg{Data: w.buf[2:]} // снять 2-байтовый префикс длины
		require.NoErrorf(t, parsed.Unpack(), "%s/%T: unpack reply", c.name, c.rr)

		require.Truef(t, parsed.Response, "%s/%T: QR bit", c.name, c.rr)
		require.EqualValuesf(t, dns.RcodeSuccess, parsed.Rcode, "%s/%T: NOERROR", c.name, c.rr)
		require.Lenf(t, parsed.Answer, 0, "%s/%T: пустой ответ (NODATA)", c.name, c.rr)
		require.Lenf(t, parsed.Ns, 1, "%s/%T: SOA в authority (негативный кэш)", c.name, c.rr)
		_, ok := parsed.Ns[0].(*dns.SOA)
		require.Truef(t, ok, "%s/%T: authority RR — SOA", c.name, c.rr)
	}
}

func TestIsDDRName(t *testing.T) {
	// на вход приходит уже нормализованное имя (без хвостовой точки)
	cases := []struct {
		domain string
		want   bool
	}{
		{"_dns.resolver.arpa", true},
		{"resolver.arpa", false},        // нет underscore-метки
		{"4.3.2.1.in-addr.arpa", false}, // обычный reverse-DNS не трогаем
		{"home.arpa", false},
		{"_foo.example.com", false}, // underscore, но не .arpa
		{"example.com", false},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, isDDRName(c.domain), "isDDRName(%q)", c.domain)
	}
}

func TestDNSHandlerNXDomainSynthesizesNameError(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "list.txt")
	require.NoError(t, os.WriteFile(listPath, []byte("dns.google"), 0o600))

	st, err := store.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	r, err := rtr.NewRouter([]cfg.Matcher{
		{Name: "doh", Type: cfg.RouterTypeNXDomain, Source: "file://" + listPath, Format: cfg.FormatPlain, Subdomains: new(true)},
	}, st, cfg.MatcherRadix)
	require.NoError(t, err)
	require.NoError(t, r.Rebuild(context.Background()))

	// resolver nil: короткое замыкание обязано ответить, не уходя в апстрим
	s := &Server{router: r, timeout: time.Second}

	for _, q := range []dns.RR{&dns.A{}, &dns.AAAA{}, &dns.HTTPS{}} {
		w := &captureWriter{}
		s.DNSHandler(context.Background(), w, typedQuery("dns.google.", q))

		require.GreaterOrEqualf(t, len(w.buf), 2, "%T: ответ записан", q)
		parsed := &dns.Msg{Data: w.buf[2:]}
		require.NoErrorf(t, parsed.Unpack(), "%T: unpack reply", q)

		require.Truef(t, parsed.Response, "%T: QR bit", q)
		require.EqualValuesf(t, dns.RcodeNameError, parsed.Rcode, "%T: NXDOMAIN", q)
		require.Lenf(t, parsed.Answer, 0, "%T: пустой answer", q)

		require.Lenf(t, parsed.Ns, 1, "%T: SOA в authority (негативный кэш)", q)
		soa, ok := parsed.Ns[0].(*dns.SOA)
		require.Truef(t, ok, "%T: authority RR — SOA", q)
		require.Equalf(t, "dns.google.", soa.Hdr.Name, "%T: SOA owner = qname", q)
		require.NotZerof(t, soa.Minttl, "%T: Minttl задан для негативного кэша", q)
	}
}

func TestDNSHandlerServfailOnResolveFailure(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	router, err := rtr.NewRouter(nil, st, cfg.MatcherRadix) // без источников → всё passthrough
	require.NoError(t, err)

	res, err := resolver.NewResolver([]cfg.Upstream{
		{Name: "dead", DSN: "udp://127.0.0.1:1", Timeout: 100 * time.Millisecond},
	}, nil)
	require.NoError(t, err)

	c := cache.NewCache(10, time.Hour, time.Second, time.Hour)
	t.Cleanup(func() { _ = c.Close() })

	s := &Server{router: router, resolver: res, cache: c, timeout: 300 * time.Millisecond}

	req := typedQuery("nothing.example.", &dns.A{})
	req.ID = 0x4321
	w := &captureWriter{}
	s.DNSHandler(context.Background(), w, req)

	require.GreaterOrEqual(t, len(w.buf), 2, "ответ записан")
	parsed := &dns.Msg{Data: w.buf[2:]}
	require.NoError(t, parsed.Unpack())
	require.True(t, parsed.Response, "QR bit установлен")
	require.EqualValues(t, dns.RcodeServerFailure, parsed.Rcode, "SERVFAIL")
	require.EqualValues(t, 0x4321, parsed.ID, "ID эхо запроса")
}

func TestRewriteRRSBestEffort(t *testing.T) {
	s := &Server{}

	a := func(name string) *dns.A { return &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}} }

	in := []dns.RR{
		a("ok1."),
		a("fail."),
		a("ok2."),
		&dns.CNAME{Hdr: dns.Header{Name: "cname.", Class: dns.ClassINET}},
		&dns.AAAA{Hdr: dns.Header{Name: "v6.", Class: dns.ClassINET}},
	}

	transform := func(rr *dns.A) (*dns.A, error) {
		if rr.Hdr.Name == "fail." {
			return nil, errors.New("boom")
		}
		return rr, nil
	}

	out, attempted, failed := s.rewriteRRS(in, transform)
	require.Equal(t, 3, attempted)
	require.Equal(t, 1, failed)

	names := map[string]bool{}
	for _, rr := range out {
		names[rr.Header().Name] = true
	}
	require.True(t, names["ok1."] && names["ok2."] && names["cname."], "успешные A и не-A проходят")
	require.False(t, names["fail."], "незамапленная A пропущена, не отдана")
	require.False(t, names["v6."], "AAAA вырезана")
}

func TestStripSvcParams(t *testing.T) {
	alpn := &svcb.ALPN{Alpn: []string{"h3"}}
	v4 := &svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	v6 := &svcb.IPV6HINT{Hint: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
	doh := &svcb.DOHPATH{Template: "/dns-query{?dns}"}

	out, changed := stripSvcParams([]svcb.Pair{alpn, v4, v6, doh})
	require.True(t, changed)
	require.Equal(t, []svcb.Pair{alpn}, out, "остаётся только не-вырезаемое (alpn); ipv4hint/ipv6hint/dohpath срезаны")

	only := []svcb.Pair{alpn}
	out2, changed2 := stripSvcParams(only)
	require.False(t, changed2, "без вырезаемых параметров — без изменений")
	require.Equal(t, only, out2)
}

func TestRewriteRRSStripsAAAAKeepsSVCBWithoutHints(t *testing.T) {
	s := &Server{}
	a := func(name string) dns.RR {
		rr := &dns.A{}
		rr.Header().Name, rr.Header().Class = name, dns.ClassINET
		return rr
	}
	aaaa := &dns.AAAA{}
	aaaa.Header().Name, aaaa.Header().Class = "v6.", dns.ClassINET

	https := &dns.HTTPS{}
	https.Header().Name, https.Header().Class = "https.", dns.ClassINET
	https.Value = []svcb.Pair{
		&svcb.ALPN{Alpn: []string{"h3"}},
		&svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.1")}},
	}
	svc := &dns.SVCB{}
	svc.Header().Name, svc.Header().Class = "svcb.", dns.ClassINET
	svc.Value = []svcb.Pair{
		&svcb.ALPN{Alpn: []string{"h2"}},
		&svcb.IPV6HINT{Hint: []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
	}

	in := []dns.RR{a("a1."), aaaa, https, svc, a("a2.")}

	out, attempted, failed := s.rewriteRRS(in, nil) // passthrough
	require.Equal(t, 0, attempted)
	require.Equal(t, 0, failed)

	names := map[string]bool{}
	var gotHTTPS *dns.HTTPS
	var gotSVCB *dns.SVCB
	for _, rr := range out {
		names[rr.Header().Name] = true
		switch v := rr.(type) {
		case *dns.HTTPS:
			gotHTTPS = v
		case *dns.SVCB:
			gotSVCB = v
		}
	}

	require.True(t, names["a1."] && names["a2."], "A проходят")
	require.False(t, names["v6."], "AAAA вырезана")
	require.True(t, names["https."] && names["svcb."], "HTTPS/SVCB остаются, не вырезаются целиком")

	isALPN := func(p svcb.Pair) bool { _, ok := p.(*svcb.ALPN); return ok }

	require.NotNil(t, gotHTTPS)
	require.False(t, slices.ContainsFunc(gotHTTPS.Value, isStrippedParam), "ipv4hint вырезан из HTTPS")
	require.True(t, slices.ContainsFunc(gotHTTPS.Value, isALPN), "alpn в HTTPS сохранён")
	require.NotNil(t, gotSVCB)
	require.False(t, slices.ContainsFunc(gotSVCB.Value, isStrippedParam), "ipv6hint вырезан из SVCB")
	require.True(t, slices.ContainsFunc(gotSVCB.Value, isALPN), "alpn в SVCB сохранён")

	// исходные записи не мутированы (cache-safety): hint остался во входном слайсе
	require.Len(t, https.Value, 2, "входной HTTPS.Value не тронут")
}
