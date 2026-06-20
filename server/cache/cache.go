package cache

import (
	"math"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/sync/singleflight"
)

const DefaultTTL = time.Duration(0)

const (
	keySep      = '|'
	keyExtraLen = 12 // 2 разделителя + до 5+5 цифр type/class
)

type Cache struct {
	cache  *ttlcache.Cache[string, *dns.Msg]
	sf     singleflight.Group
	minTTL time.Duration
	maxTTL time.Duration
}

func NewCache(capacity uint64, defaultTTL, minTTL, maxTTL time.Duration) (c *Cache) {
	c = &Cache{
		minTTL: minTTL,
		maxTTL: maxTTL,
		cache: ttlcache.New(
			ttlcache.WithCapacity[string, *dns.Msg](capacity),
			ttlcache.WithTTL[string, *dns.Msg](defaultTTL),
			ttlcache.WithDisableTouchOnHit[string, *dns.Msg](),
		),
	}

	go c.cache.Start()

	return c
}

func (c *Cache) GetResponse(req *dns.Msg, name string) *dns.Msg {
	if name == "" || len(req.Question) != 1 {
		return nil
	}
	q := req.Question[0]
	return c.getByKey(req, cacheKey(name, dns.RRToType(q), q.Header().Class))
}

func (c *Cache) getByKey(req *dns.Msg, key string) (resp *dns.Msg) {
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

	// Msg.Copy() поверхностный — RR шарятся с кэш-записью. Клонируем те, чьим
	// TTL правим, иначе пишем в общий объект: гонка на конкурентных hit'ах + порча кэша.
	resp.Answer = cloneWithTTL(resp.Answer, ttl)
	resp.Ns = cloneWithTTL(resp.Ns, ttl)
	resp.Extra = cloneWithTTL(resp.Extra, ttl)

	return
}

func cloneWithTTL(in []dns.RR, ttl uint32) []dns.RR {
	if len(in) == 0 {
		return in
	}
	out := make([]dns.RR, len(in))
	for i, rr := range in {
		cp := rr.Clone()
		cp.Header().TTL = ttl
		out[i] = cp
	}
	return out
}

func (c *Cache) GetResponseLambda(req *dns.Msg, name string, lambda func() (*dns.Msg, time.Duration, error)) (resp *dns.Msg) {
	// Неключуемое имя коалесцировать нельзя: пустой ключ слил бы все такие запросы в один ответ.
	if name == "" || len(req.Question) != 1 {
		resp, _, _ = lambda()
		return resp
	}

	q := req.Question[0]
	key := cacheKey(name, dns.RRToType(q), q.Header().Class)

	if resp = c.getByKey(req, key); resp != nil {
		return resp
	}

	shared, _, _ := c.sf.Do(key, func() (any, error) {
		r, ttl, err := lambda()
		if err == nil && r != nil {
			stored := r.Copy()
			stored.Data = nil
			c.setByKey(stored, key, ttl)
		}
		return r, nil
	})

	r, _ := shared.(*dns.Msg)
	if r == nil {
		return nil
	}

	resp = r.Copy()
	resp.Data = nil
	resp.ID = req.ID
	return resp
}

func (c *Cache) SetResponse(req, resp *dns.Msg, name string, ttl time.Duration) {
	if name == "" || len(req.Question) != 1 {
		return
	}
	q := req.Question[0]
	c.setByKey(resp, cacheKey(name, dns.RRToType(q), q.Header().Class), ttl)
}

func (c *Cache) setByKey(resp *dns.Msg, key string, ttl time.Duration) {
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return
	}

	if ttl == DefaultTTL {
		if resp.Rcode == dns.RcodeNameError {
			// RFC 2308: негативный TTL = min(TTL заголовка SOA, SOA.MINIMUM);
			// NXDOMAIN без SOA в authority негативно не кэшируется
			var soa *dns.SOA
			for _, rr := range resp.Ns {
				if s, ok := rr.(*dns.SOA); ok {
					soa = s
					break
				}
			}
			if soa == nil {
				return
			}
			ttl = time.Duration(min(soa.Hdr.TTL, soa.Minttl)) * time.Second
		} else {
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
	}

	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl < c.minTTL {
		ttl = c.minTTL
	}

	c.cache.Set(key, resp, ttl)
}

func cacheKey(name string, qtype, qclass uint16) string {
	var b strings.Builder
	b.Grow(len(name) + keyExtraLen)
	b.WriteString(name)
	b.WriteByte(keySep)
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	b.WriteByte(keySep)
	b.WriteString(strconv.FormatUint(uint64(qclass), 10))
	return b.String()
}

func (c *Cache) Close() error {
	c.cache.Stop()
	return nil
}
