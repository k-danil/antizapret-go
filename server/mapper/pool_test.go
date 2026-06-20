package mapper

import (
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/k-danil/antizapret-go/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustPool(t *testing.T, cidr string) *ipPool {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	require.NoError(t, err)
	return newIPPool(ipnet)
}

func u32(a, b, c, d byte) uint32 {
	return utils.IPToUint32(net.IPv4(a, b, c, d))
}

func TestIPPoolFreshSequential(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")
	base := u32(10, 0, 0, 0)

	for i := range uint32(255) {
		ip, ok := p.allocate()
		require.True(t, ok)
		require.Equal(t, base+i, ip)
	}

	_, ok := p.allocate()
	require.False(t, ok, "пул должен исчерпаться после 255 выдач (/24)")
}

func TestIPPoolExhaustion(t *testing.T) {
	p := mustPool(t, "10.0.0.0/30") // .0 .1 .2 — три адреса

	got := 0
	for {
		_, ok := p.allocate()
		if !ok {
			break
		}
		got++
		require.LessOrEqual(t, got, 3, "защита от бесконечного цикла")
	}
	require.Equal(t, 3, got)
}

func TestIPPoolFreedFIFO(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")

	a, _ := p.allocate()
	b, _ := p.allocate()
	c, _ := p.allocate()

	p.release(a)
	p.release(b)
	p.release(c)

	g1, _ := p.allocate()
	g2, _ := p.allocate()
	g3, _ := p.allocate()
	require.Equal(t, []uint32{a, b, c}, []uint32{g1, g2, g3}, "freed переиспользуется в FIFO-порядке")

	g4, _ := p.allocate()
	require.Equal(t, c+1, g4, "после опустошения freed cursor продолжает с места")
}

func TestIPPoolFreedBeforeCursor(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")

	a, _ := p.allocate()
	p.release(a)

	g, _ := p.allocate()
	require.Equal(t, a, g, "освобождённый адрес приоритетнее свежего из cursor")
}

func TestIPPoolAdoptedSkipped(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")
	base := u32(10, 0, 0, 0)

	p.markAdopted(base + 5)
	p.markAdopted(base + 10)

	seen := map[uint32]struct{}{}
	for {
		ip, ok := p.allocate()
		if !ok {
			break
		}
		require.NotEqual(t, base+5, ip, "усыновлённый адрес не должен выдаваться cursor")
		require.NotEqual(t, base+10, ip)
		_, dup := seen[ip]
		require.Falsef(t, dup, "повторная выдача %d", ip)
		seen[ip] = struct{}{}
	}

	require.Len(t, seen, 255-2)
	require.Nil(t, p.adopted, "после прохода cursor за maxAdopt сет должен обнулиться")
}

func TestIPPoolAdoptedReleasedReusable(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")
	base := u32(10, 0, 0, 0)
	x := base + 5

	p.markAdopted(x)
	p.release(x)

	g, _ := p.allocate()
	require.Equal(t, x, g, "освобождённый усыновлённый адрес возвращается через freed")

	for {
		ip, ok := p.allocate()
		if !ok {
			break
		}
		require.NotEqual(t, x, ip, "cursor не должен выдать усыновлённый адрес повторно")
	}
}

func TestIPPoolFIFOAcrossCompaction(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24")
	base := u32(10, 0, 0, 0)

	for range 10 {
		_, _ = p.allocate()
	}
	for i := range 10 {
		p.release(base + uint32(i)) // freed = base+0..9
	}

	for i := range 5 { // head=5, len=10 (мёртвый префикс == живому хвосту)
		ip, _ := p.allocate()
		require.Equal(t, base+uint32(i), ip)
	}

	p.release(base + 0) // триггерит компакцию: freed -> [5,6,7,8,9,0], head=0
	require.Zero(t, p.head, "компакция сбрасывает head")

	want := []uint32{base + 5, base + 6, base + 7, base + 8, base + 9, base + 0}
	for _, w := range want {
		ip, ok := p.allocate()
		require.True(t, ok)
		require.Equal(t, w, ip, "FIFO-порядок сохраняется после компакции")
	}
}

func TestIPPoolNoDoubleAllocationStress(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24") // ёмкость 255
	rng := rand.New(rand.NewSource(1))

	outstanding := map[uint32]struct{}{}
	var live []uint32

	for i := range 200000 {
		if len(live) > 0 && rng.Intn(2) == 0 {
			j := rng.Intn(len(live))
			ip := live[j]
			live[j] = live[len(live)-1]
			live = live[:len(live)-1]
			delete(outstanding, ip)
			p.release(ip)
			continue
		}

		ip, ok := p.allocate()
		if !ok {
			continue
		}
		_, dup := outstanding[ip]
		require.Falsef(t, dup, "двойная выдача %d на итерации %d", ip, i)
		outstanding[ip] = struct{}{}
		live = append(live, ip)
	}

	require.LessOrEqual(t, len(outstanding), 255)
	require.LessOrEqual(t, cap(p.freed), 1024, "backing-массив freed должен оставаться ограниченным")
}

func TestIPPoolConcurrent(t *testing.T) {
	p := mustPool(t, "10.0.0.0/16") // ёмкость 65535
	const (
		workers   = 16
		perWorker = 5000
		holdBatch = 8
	)

	var mu sync.Mutex
	outstanding := map[uint32]struct{}{}

	take := func(ip uint32) {
		mu.Lock()
		defer mu.Unlock()
		if _, dup := outstanding[ip]; dup {
			assert.Failf(t, "двойная выдача fake", "ip=%d", ip)
			return
		}
		outstanding[ip] = struct{}{}
	}
	drop := func(ip uint32) {
		mu.Lock()
		delete(outstanding, ip)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			var held []uint32
			flush := func() {
				for _, h := range held {
					drop(h)
					p.release(h)
				}
				held = held[:0]
			}
			for range perWorker {
				ip, ok := p.allocate()
				if !ok {
					flush()
					continue
				}
				take(ip)
				held = append(held, ip)
				if len(held) >= holdBatch {
					flush()
				}
			}
			flush()
		})
	}
	wg.Wait()
}

func BenchmarkIPPoolAllocateCursor(b *testing.B) {
	_, ipnet, _ := net.ParseCIDR("0.0.0.0/0") // не исчерпается на любом b.N
	p := newIPPool(ipnet)
	b.ReportAllocs()
	for b.Loop() {
		p.allocate()
	}
}

func BenchmarkIPPoolAllocReleaseCycle(b *testing.B) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/16")
	p := newIPPool(ipnet)
	b.ReportAllocs()
	for b.Loop() {
		ip, _ := p.allocate()
		p.release(ip)
	}
}

func BenchmarkIPPoolConstruct(b *testing.B) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		_ = newIPPool(ipnet)
	}
}

func BenchmarkIPPoolAllocReleaseParallel(b *testing.B) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/16")
	p := newIPPool(ipnet)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ip, ok := p.allocate(); ok {
				p.release(ip)
			}
		}
	})
}
