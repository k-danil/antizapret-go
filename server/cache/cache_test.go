package cache

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testName = "a.test"

func aQuery(name string) *dns.Msg {
	return &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET}}}}
}

func aResp(name string, answerTTL uint32) *dns.Msg {
	m := aQuery(name)
	m.Answer = []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: answerTTL},
		Addr: netip.AddrFrom4([4]byte{1, 2, 3, 4}),
	}}
	return m
}

func nxResp(name string, soaTTL, soaMin uint32) *dns.Msg {
	m := aQuery(name)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.Header{Name: "test.", Class: dns.ClassINET, TTL: soaTTL},
		Ns:     "ns.test.",
		Mbox:   "host.test.",
		Minttl: soaMin,
	}}
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

func lambdaFor(resp *dns.Msg) func() (*dns.Msg, time.Duration, error) {
	return func() (*dns.Msg, time.Duration, error) { return resp, defaultTTL, nil }
}

func TestCacheTTLClamping(t *testing.T) {
	tests := []struct {
		name                    string
		resp                    *dns.Msg
		wantTTLLow, wantTTLHigh uint32
	}{
		{"short ttl clamped up to min", aResp("a.test.", 5), 55, 60},
		{"long ttl capped at max", aResp("a.test.", 360000), 3595, 3600},
		{"negative ttl from soa minimum", nxResp("a.test.", 600, 90), 85, 90},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(100, time.Hour, 60*time.Second, 3600*time.Second)
			defer func() { _ = c.Close() }()

			req := aQuery("a.test.")
			c.GetResponseLambda(req, testName, lambdaFor(tc.resp))
			got, hit := c.GetResponseLambda(req, testName, lambdaFor(nil))
			require.True(t, hit, "response must be cached")

			ttl := effectiveTTL(got)
			assert.GreaterOrEqual(t, ttl, tc.wantTTLLow)
			assert.LessOrEqual(t, ttl, tc.wantTTLHigh)
		})
	}
}

func TestGetResponseReturnsIndependentRRs(t *testing.T) {
	c := NewCache(100, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	c.GetResponseLambda(req, testName, lambdaFor(aResp("a.test.", 600)))

	r1, _ := c.GetResponseLambda(req, testName, lambdaFor(nil))
	r2, _ := c.GetResponseLambda(req, testName, lambdaFor(nil))
	require.NotNil(t, r1)
	require.NotNil(t, r2)
	require.NotSame(t, r1.Answer[0].(*dns.A), r2.Answer[0].(*dns.A),
		"каждая отдача — своя копия RR, не общий объект кэша")
}
