package server

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
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

func TestDNSHandlerSuppressesHTTPSAndSVCBForRemap(t *testing.T) {
	s := remapServer(t, "blocked.test")

	for _, q := range []dns.RR{&dns.HTTPS{}, &dns.SVCB{}} {
		w := &captureWriter{}
		s.DNSHandler(context.Background(), w, typedQuery("blocked.test.", q))

		require.GreaterOrEqualf(t, len(w.buf), 2, "%T: ответ записан", q)
		parsed := &dns.Msg{Data: w.buf[2:]} // снять 2-байтовый префикс длины
		require.NoErrorf(t, parsed.Unpack(), "%T: unpack reply", q)

		require.Truef(t, parsed.Response, "%T: QR bit (не эхо запроса)", q)
		require.EqualValuesf(t, dns.RcodeSuccess, parsed.Rcode, "%T: NOERROR", q)
		require.Lenf(t, parsed.Answer, 0, "%T: пустой ответ (NODATA)", q)
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
