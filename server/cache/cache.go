package cache

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jellydator/ttlcache/v3"
)

type Cache struct {
	cache *ttlcache.Cache[string, *dns.Msg]
}

func NewCache(capacity uint64, defaultTTL time.Duration) (c *Cache) {
	c = &Cache{
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

	ttl := uint32(item.ExpiresAt().Sub(time.Now()).Seconds())
	resp = item.Value().Copy()
	resp.ID = req.ID

	for _, rr := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, a := range rr {
			a.Header().TTL = ttl
		}
	}

	return
}

func (c *Cache) SetResponse(req, resp *dns.Msg) {
	l := len(req.Question)
	if l == 0 || l > 1 {
		return
	}

	key := c.calculateCacheKey(req)
	ttl := uint32(math.MaxUint32)
	for _, rr := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, a := range rr {
			ttl = min(ttl, a.Header().TTL)
		}
	}

	c.cache.Set(key, resp.Copy(), time.Duration(ttl)*time.Second)
	return
}

func (c *Cache) calculateCacheKey(req *dns.Msg) string {
	return fmt.Sprintf("%s-%s", req.Question[0].Header().Name, reflect.TypeOf(req.Question[0]))
}
