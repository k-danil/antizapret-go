package mapper

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/k-danil/antizapret-go/utils"
	"github.com/stretchr/testify/require"
)

func mustPool(t *testing.T, cidr string) *ipPool {
	t.Helper()
	prefix, err := netip.ParsePrefix(cidr)
	require.NoError(t, err)
	return newIPPool(prefix)
}

func u32(a, b, c, d byte) uint32 {
	return utils.AddrToUint32(netip.AddrFrom4([4]byte{a, b, c, d}))
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
}

func TestIPPoolNoDoubleAllocationStress(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24") // ёмкость 255
	rng := rand.New(rand.NewPCG(1, 2))

	outstanding := map[uint32]struct{}{}
	var live []uint32

	for i := range 200000 {
		if len(live) > 0 && rng.IntN(2) == 0 {
			j := rng.IntN(len(live))
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
}
