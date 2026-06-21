package cache

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
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
			c.SetResponse(req, tc.resp, testName, tc.ttl)
			got := c.GetResponse(req, testName)
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
			c.SetResponse(req, tc.resp, testName, DefaultTTL)
			got := c.GetResponse(req, testName)
			require.NotNil(t, got, "response must be cached")

			ttl := effectiveTTL(got)
			assert.GreaterOrEqual(t, ttl, tc.wantTTLLow)
			assert.LessOrEqual(t, ttl, tc.wantTTLHigh)
		})
	}
}

func TestCacheKey(t *testing.T) {
	aKey := cacheKey("example.com", uint16(dns.TypeA), uint16(dns.ClassINET))

	require.Equal(t, aKey, cacheKey("example.com", uint16(dns.TypeA), uint16(dns.ClassINET)), "детерминирован")
	require.NotEqual(t, aKey, cacheKey("example.com", uint16(dns.TypeAAAA), uint16(dns.ClassINET)), "qtype различает ключи")
	require.NotEqual(t, aKey, cacheKey("other.com", uint16(dns.TypeA), uint16(dns.ClassINET)), "имя различает ключи")
}

func TestCacheBypassEmptyName(t *testing.T) {
	c := NewCache(10, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	c.SetResponse(req, aResp("a.test.", dns.RcodeSuccess, 600, true), "", DefaultTTL)
	require.Nil(t, c.GetResponse(req, ""), "пустое имя не кэшируется и всегда промах")
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

	c.GetResponseLambda(req, testName, lambda)
	c.GetResponseLambda(req, testName, lambda)

	assert.Equal(t, 1, calls, "second call must hit cache")
}

func TestGetResponseLambdaSingleflight(t *testing.T) {
	c := NewCache(100, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	var calls atomic.Int64
	lambda := func() (*dns.Msg, time.Duration, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // окно для коалесценса конкурентных промахов
		return aResp("a.test.", dns.RcodeSuccess, 600, true), DefaultTTL, nil
	}

	const n = 50
	results := make([]*dns.Msg, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			results[i], _ = c.GetResponseLambda(req, testName, lambda)
		})
	}
	wg.Wait()

	require.Equal(t, int64(1), calls.Load(), "конкурентные промахи одного ключа → один резолв в апстрим")
	for i := range n {
		require.NotNil(t, results[i], "каждый вызывающий получает ответ")
	}
}

func TestGetResponseReturnsIndependentRRs(t *testing.T) {
	c := NewCache(100, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	c.SetResponse(req, aResp("a.test.", dns.RcodeSuccess, 600, true), testName, DefaultTTL)

	r1 := c.GetResponse(req, testName)
	r2 := c.GetResponse(req, testName)
	require.NotNil(t, r1)
	require.NotNil(t, r2)
	require.NotSame(t, r1.Answer[0].(*dns.A), r2.Answer[0].(*dns.A),
		"каждая отдача — своя копия RR, не общий объект кэша")

	// конкурентные hit'ы одного ключа не должны гонять по общему RR (под -race)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				_ = c.GetResponse(req, testName)
			}
		})
	}
	wg.Wait()
}

func TestGetResponseLambdaNilOnFailure(t *testing.T) {
	c := NewCache(10, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	req := aQuery("a.test.")
	resp, _ := c.GetResponseLambda(req, testName, func() (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("resolve failed")
	})
	require.Nil(t, resp, "на сбое lambda кэш отдаёт nil — хэндлер синтезирует свой SERVFAIL")

	// сбой не должен кэшироваться: следующий вызов реально резолвит
	called := false
	resp, _ = c.GetResponseLambda(req, testName, func() (*dns.Msg, time.Duration, error) {
		called = true
		return aResp("a.test.", dns.RcodeSuccess, 60, true), DefaultTTL, nil
	})
	require.True(t, called, "сбой не должен был закэшироваться")
	require.NotNil(t, resp)
}

func BenchmarkCacheKey(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = cacheKey("www.example.com", uint16(dns.TypeA), uint16(dns.ClassINET))
	}
}
