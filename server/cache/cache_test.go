package cache

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aQuery(name string) *dns.Msg {
	return &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}}}}
}

func aResp(name string, rcode uint16, answerTTL uint32, withAnswer bool) *dns.Msg {
	m := aQuery(name)
	m.Rcode = rcode
	if withAnswer {
		a := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: answerTTL}}
		a.Addr = netip.AddrFrom4([4]byte{1, 2, 3, 4})
		m.Answer = []dns.RR{a}
	}
	return m
}

func nxResp(name string, soaTTL, soaMin uint32, withSOA bool) *dns.Msg {
	m := aQuery(name)
	m.Rcode = dns.RcodeNameError
	if withSOA {
		soa := &dns.SOA{Hdr: dns.Header{Name: "test.", Class: dns.ClassINET, TTL: soaTTL}}
		soa.Ns = "ns.test."
		soa.Mbox = "host.test."
		soa.Minttl = soaMin
		m.Ns = []dns.RR{soa}
	}
	return m
}

func effectiveTTL(m *dns.Msg) uint32 {
	if len(m.Answer) > 0 {
		return m.Answer[0].Header().TTL
	}
	if len(m.Ns) > 0 {
		return m.Ns[0].Header().TTL
	}
	return 0
}

func TestSetResponseCachingRules(t *testing.T) {
	tests := []struct {
		name   string
		resp   *dns.Msg
		ttl    time.Duration
		cached bool
	}{
		{"success with cacheable ttl", aResp("a.test.", dns.RcodeSuccess, 600, true), DefaultTTL, true},
		{"servfail not cached", aResp("a.test.", dns.RcodeServerFailure, 600, false), DefaultTTL, false},
		{"nxdomain with explicit ttl cached", nxResp("a.test.", 0, 0, false), 24 * time.Hour, true},
		{"success empty records not cached", aResp("a.test.", dns.RcodeSuccess, 0, false), DefaultTTL, false},
		{"success short ttl cached (clamped up)", aResp("a.test.", dns.RcodeSuccess, 3, true), DefaultTTL, true},
		{"nxdomain with soa cached (rfc 2308)", nxResp("a.test.", 600, 60, true), DefaultTTL, true},
		{"nxdomain without soa not cached", nxResp("a.test.", 0, 0, false), DefaultTTL, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(100, time.Hour, time.Second, time.Hour)
			defer func() { _ = c.Close() }()

			req := aQuery("a.test.")
			c.SetResponse(req, tc.resp, tc.ttl)
			got := c.GetResponse(req)
			if tc.cached {
				require.NotNil(t, got)
			} else {
				require.Nil(t, got)
			}
		})
	}
}

func TestCacheTTLClamping(t *testing.T) {
	tests := []struct {
		name                    string
		resp                    *dns.Msg
		wantTTLLow, wantTTLHigh uint32
	}{
		{"short ttl clamped up to min", aResp("a.test.", dns.RcodeSuccess, 5, true), 55, 60},
		{"long ttl capped at max", aResp("a.test.", dns.RcodeSuccess, 360000, true), 3595, 3600},
		{"negative ttl from soa minimum", nxResp("a.test.", 600, 90, true), 85, 90},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(100, time.Hour, 60*time.Second, 3600*time.Second)
			defer func() { _ = c.Close() }()

			req := aQuery("a.test.")
			c.SetResponse(req, tc.resp, DefaultTTL)
			got := c.GetResponse(req)
			require.NotNil(t, got, "response must be cached")

			ttl := effectiveTTL(got)
			assert.GreaterOrEqual(t, ttl, tc.wantTTLLow)
			assert.LessOrEqual(t, ttl, tc.wantTTLHigh)
		})
	}
}

func TestCalculateCacheKey(t *testing.T) {
	aaaaQuery := &dns.Msg{Question: []dns.RR{&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}

	tests := []struct {
		name     string
		a, b     *dns.Msg
		wantSame bool
	}{
		{"qtype distinguishes keys", aQuery("example.com."), aaaaQuery, false},
		{"case normalizes to same key", aQuery("Example.COM."), aQuery("example.com."), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(10, time.Hour, time.Second, time.Hour)
			defer func() { _ = c.Close() }()

			if tc.wantSame {
				assert.Equal(t, c.calculateCacheKey(tc.a), c.calculateCacheKey(tc.b))
			} else {
				assert.NotEqual(t, c.calculateCacheKey(tc.a), c.calculateCacheKey(tc.b))
			}
		})
	}
}

func TestGetResponseLambdaCachesOnMiss(t *testing.T) {
	c := NewCache(100, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	calls := 0
	lambda := func() (*dns.Msg, time.Duration, error) {
		calls++
		return aResp("a.test.", dns.RcodeSuccess, 600, true), DefaultTTL, nil
	}

	c.GetResponseLambda(req, lambda)
	c.GetResponseLambda(req, lambda)

	assert.Equal(t, 1, calls, "second call must hit cache")
}
