package cache

import (
	"fmt"
	"math"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jellydator/ttlcache/v3"
)

const DefaultTTL = time.Duration(0)

type Cache struct {
	cache  *ttlcache.Cache[string, *dns.Msg]
	minTTL time.Duration
	maxTTL time.Duration
}

func NewCache(capacity uint64, defaultTTL, minTTL, maxTTL time.Duration) (c *Cache) {
	c = &Cache{
		minTTL: minTTL,
		maxTTL: maxTTL,
		cache: ttlcache.New[string, *dns.Msg](
			ttlcache.WithCapacity[string, *dns.Msg](capacity),
			ttlcache.WithTTL[string, *dns.Msg](defaultTTL),
			ttlcache.WithDisableTouchOnHit[string, *dns.Msg](),
		),
	}

	go c.cache.Start()

	return c
}

func (c *Cache) GetResponse(req *dns.Msg) (resp *dns.Msg) {
	l := len(req.Question)
	if l == 0 || l > 1 {
		return
	}

	key := c.calculateCacheKey(req)
	item := c.cache.Get(key)
	if item == nil {
		return
	}

	itemTTL := time.Until(item.ExpiresAt())
	if itemTTL <= 0 {
		return
	}

	ttl := uint32(itemTTL.Seconds())
	resp = item.Value().Copy()
	resp.ID = req.ID

	for _, rr := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, a := range rr {
			a.Header().TTL = ttl
		}
	}

	return
}

func (c *Cache) GetResponseLambda(req *dns.Msg, lambda func() (*dns.Msg, time.Duration, error)) (resp *dns.Msg) {
	resp = c.GetResponse(req)
	if resp != nil {
		return resp
	}

	var ttl time.Duration
	var err error
	resp, ttl, err = lambda()
	if err != nil {
		return
	}

	resp = resp.Copy()
	resp.Data = nil

	c.SetResponse(req, resp, ttl)
	return resp.Copy()
}

func (c *Cache) SetResponse(req, resp *dns.Msg, ttl time.Duration) {
	l := len(req.Question)
	if l == 0 || l > 1 {
		return
	}

	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return
	}

	if ttl == DefaultTTL {
		ttlUint := uint32(math.MaxUint32)
		for _, rr := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
			for _, a := range rr {
				ttlUint = min(ttlUint, a.Header().TTL)
			}
		}
		if ttlUint == math.MaxUint32 {
			return
		}
		ttl = time.Duration(ttlUint) * time.Second
	}

	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}

	c.cache.Set(c.calculateCacheKey(req), resp, ttl)
}

func (c *Cache) calculateCacheKey(req *dns.Msg) string {
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Header().Name, "."))
	return fmt.Sprintf("%s|%d|%d", name, dns.RRToType(q), q.Header().Class)
}

func (c *Cache) Close() error {
	c.cache.Stop()
	return nil
}
