package cache

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
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

func TestSetResponseCachingRules(t *testing.T) {
	tests := []struct {
		name   string
		resp   *dns.Msg
		ttl    time.Duration
		cached bool
	}{
		{"success with cacheable ttl", aResp("a.test.", dns.RcodeSuccess, 600, true), DefaultTTL, true},
		{"servfail not cached", aResp("a.test.", dns.RcodeServerFailure, 600, false), DefaultTTL, false},
		{"nxdomain with explicit ttl cached", aResp("a.test.", dns.RcodeNameError, 0, false), 24 * time.Hour, true},
		{"success empty records not cached", aResp("a.test.", dns.RcodeSuccess, 0, false), DefaultTTL, false},
		{"success short ttl cached (clamped up)", aResp("a.test.", dns.RcodeSuccess, 3, true), DefaultTTL, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(100, time.Hour, time.Second, time.Hour)
			defer func() { _ = c.Close() }()

			req := aQuery("a.test.")
			c.SetResponse(req, tc.resp, tc.ttl)
			if got := c.GetResponse(req) != nil; got != tc.cached {
				t.Fatalf("cached = %v, want %v", got, tc.cached)
			}
		})
	}
}

func TestCacheClampsTTL(t *testing.T) {
	c := NewCache(100, time.Hour, 60*time.Second, 3600*time.Second)
	defer func() { _ = c.Close() }()

	reqShort := aQuery("short.test.")
	c.SetResponse(reqShort, aResp("short.test.", dns.RcodeSuccess, 5, true), DefaultTTL)
	short := c.GetResponse(reqShort)
	if short == nil {
		t.Fatal("short-ttl answer must be cached (clamped up to min)")
	}
	if got := short.Answer[0].Header().TTL; got < 55 || got > 60 {
		t.Fatalf("min-clamped ttl = %d, want ~60", got)
	}

	reqLong := aQuery("long.test.")
	c.SetResponse(reqLong, aResp("long.test.", dns.RcodeSuccess, 360000, true), DefaultTTL)
	long := c.GetResponse(reqLong)
	if long == nil {
		t.Fatal("long-ttl answer must be cached")
	}
	if got := long.Answer[0].Header().TTL; got < 3595 || got > 3600 {
		t.Fatalf("max-capped ttl = %d, want ~3600", got)
	}
}

func TestCacheKeyDistinguishesType(t *testing.T) {
	c := NewCache(10, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	a := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	aaaa := &dns.Msg{Question: []dns.RR{&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	if c.calculateCacheKey(a) == c.calculateCacheKey(aaaa) {
		t.Fatal("A and AAAA must not collapse to the same cache key")
	}
}

func TestCacheKeyNormalizesName(t *testing.T) {
	c := NewCache(10, time.Hour, time.Second, time.Hour)
	defer func() { _ = c.Close() }()

	upper := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "Example.COM.", Class: dns.ClassINET}}}}
	lower := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	if c.calculateCacheKey(upper) != c.calculateCacheKey(lower) {
		t.Fatal("case and trailing dot must normalize to the same key")
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

	if calls != 1 {
		t.Fatalf("lambda called %d times, want 1 (second call must hit cache)", calls)
	}
}
