package mapper

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/utils"
)

var (
	errNoFreeIPs = errors.New("no free IPs")
	errNotIPv4   = errors.New("address is not IPv4")
)

type IPMapper struct {
	table *mappingTable
	pool  *ipPool

	ttl time.Duration
	fw  firewall.Manager

	sf singleflight.Group

	cleanMu sync.Mutex
	pending []pair
}

func NewIPMapper(cidr string, ttl time.Duration, fw firewall.Manager) (m *IPMapper, err error) {
	var prefix netip.Prefix
	if prefix, err = netip.ParsePrefix(cidr); err != nil {
		err = fmt.Errorf("failed to parse CIDR: %w", err)
		return
	}
	if !prefix.Addr().Is4() {
		err = fmt.Errorf("fake CIDR `%s` is not IPv4", cidr)
		return
	}

	m = &IPMapper{
		table: newMappingTable(),
		pool:  newIPPool(prefix),
		ttl:   ttl,
		fw:    fw,
	}

	if err = m.adopt(); err != nil {
		return nil, err
	}
	return
}

func (m *IPMapper) adopt() (err error) {
	var existing []firewall.Mapping
	if existing, err = m.fw.List(); err != nil {
		return fmt.Errorf("failed to list existing mappings: %w", err)
	}

	for _, mp := range existing {
		if !mp.Fake.Is4() || !mp.Real.Is4() {
			log.L.Warnw("skipping non-IPv4 mapping on adopt", "fake", mp.Fake, "real", mp.Real)
			continue
		}

		fakeU := utils.AddrToUint32(mp.Fake)
		realU := utils.AddrToUint32(mp.Real)

		if !m.pool.inRange(fakeU) || m.pool.isAdopted(fakeU) || m.table.has(realU) {
			if delErr := m.fw.Delete([]firewall.Mapping{mp}); delErr != nil {
				log.L.Warnw("failed to drop stale mapping on adopt",
					"fake", mp.Fake, "real", mp.Real, "err", delErr)
			}
			continue
		}

		m.pool.markAdopted(fakeU)
		m.table.set(realU, fakeU)
	}
	return
}

func (m *IPMapper) Map(realIP netip.Addr) (fakeIP netip.Addr, err error) {
	if !realIP.Is4() {
		err = errNotIPv4
		return
	}
	realU := utils.AddrToUint32(realIP)

	if fakeU, ok := m.table.get(realU); ok {
		return utils.Uint32ToAddr(fakeU), nil
	}

	v, doErr, _ := m.sf.Do(strconv.FormatUint(uint64(realU), 10), func() (any, error) {
		// singleflight коалесцирует лишь конкурентные вызовы; после закрытия ключа нужен повторный get
		if fakeU, ok := m.table.get(realU); ok {
			return fakeU, nil
		}

		fakeU, ok := m.pool.allocate()
		if !ok {
			return uint32(0), errNoFreeIPs
		}
		if addErr := m.fw.Add(firewall.Mapping{Fake: utils.Uint32ToAddr(fakeU), Real: realIP}); addErr != nil {
			m.pool.release(fakeU)
			return uint32(0), addErr
		}
		m.table.set(realU, fakeU)
		return fakeU, nil
	})
	if doErr != nil {
		err = doErr
		return
	}

	fakeIP = utils.Uint32ToAddr(v.(uint32))
	return
}

func (m *IPMapper) Clean() (err error) {
	m.cleanMu.Lock()
	defer m.cleanMu.Unlock()

	items := append(m.pending, m.table.expired(m.ttl)...)
	m.pending, err = m.teardown(items)
	return
}

func (m *IPMapper) teardown(items []pair) (failed []pair, err error) {
	if len(items) == 0 {
		return
	}

	mappings := make([]firewall.Mapping, len(items))
	for i, p := range items {
		mappings[i] = firewall.Mapping{Fake: utils.Uint32ToAddr(p.fake), Real: utils.Uint32ToAddr(p.real)}
	}

	if err = m.fw.Delete(mappings); err != nil {
		failed = items
		return
	}

	for _, p := range items {
		m.pool.release(p.fake)
	}
	return
}

func (m *IPMapper) GetTTL() time.Duration {
	return m.ttl
}

func (m *IPMapper) Stats() (active, capacity int) {
	return m.table.Len(), int(m.pool.capacity())
}
