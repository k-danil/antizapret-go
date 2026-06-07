package cache

import (
	"net"
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
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: answerTTL},
			A:   net.IPv4(1, 2, 3, 4),
		}}
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
		{"success ttl below floor not cached", aResp("a.test.", dns.RcodeSuccess, 3, true), DefaultTTL, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCache(100, time.Hour)
			defer func() { _ = c.Close() }()

			req := aQuery("a.test.")
			c.SetResponse(req, tc.resp, tc.ttl)
			if got := c.GetResponse(req) != nil; got != tc.cached {
				t.Fatalf("cached = %v, want %v", got, tc.cached)
			}
		})
	}
}

func TestCacheKeyDistinguishesType(t *testing.T) {
	c := NewCache(10, time.Hour)
	defer func() { _ = c.Close() }()

	a := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	aaaa := &dns.Msg{Question: []dns.RR{&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	if c.calculateCacheKey(a) == c.calculateCacheKey(aaaa) {
		t.Fatal("A and AAAA must not collapse to the same cache key")
	}
}

func TestCacheKeyNormalizesName(t *testing.T) {
	c := NewCache(10, time.Hour)
	defer func() { _ = c.Close() }()

	upper := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "Example.COM.", Class: dns.ClassINET}}}}
	lower := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}}
	if c.calculateCacheKey(upper) != c.calculateCacheKey(lower) {
		t.Fatal("case and trailing dot must normalize to the same key")
	}
}

func TestGetResponseLambdaCachesOnMiss(t *testing.T) {
	c := NewCache(100, time.Hour)
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
