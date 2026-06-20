package mapper

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/utils"
)

var errNoFreeIPs = errors.New("no free IPs")

type IPMapper struct {
	table *mappingTable
	pool  *ipPool

	ttl time.Duration
	fw  firewall.Manager

	sf singleflight.Group

	// pending трогает только Clean, а cleanMu сериализует Clean-vs-Clean — отдельная синхронизация не нужна
	cleanMu sync.Mutex
	pending []pair
}

func NewIPMapper(cidr string, ttl time.Duration, fw firewall.Manager) (m *IPMapper, err error) {
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
		err = fmt.Errorf("failed to parse CIDR: %w", err)
		return
	}

	m = &IPMapper{
		table: newMappingTable(),
		pool:  newIPPool(ipnet),
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
		if mp.Fake.To4() == nil || mp.Real.To4() == nil {
			// чужой/не-v4 элемент в наборе — не наш; пропускаем (IPToUint32 иначе паникует)
			log.L.Warnw("skipping non-IPv4 mapping on adopt", "fake", mp.Fake, "real", mp.Real)
			continue
		}

		fakeU := utils.IPToUint32(mp.Fake)
		realU := utils.IPToUint32(mp.Real)

		if !m.pool.inRange(fakeU) || m.pool.isAdopted(fakeU) || m.table.has(realU) {
			if delErr := m.fw.Delete(mp); delErr != nil {
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

func (m *IPMapper) Map(realIP net.IP) (fakeIP net.IP, err error) {
	realU := utils.IPToUint32(realIP)

	if fakeU, ok := m.table.get(realU); ok {
		return utils.Uint32ToIP(fakeU), nil
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
		if addErr := m.fw.Add(firewall.Mapping{Fake: utils.Uint32ToIP(fakeU), Real: realIP}); addErr != nil {
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

	fakeIP = utils.Uint32ToIP(v.(uint32))
	return
}

func (m *IPMapper) Clean() (err error) {
	m.cleanMu.Lock()
	defer m.cleanMu.Unlock()

	var errs []error
	retryFailed := m.teardown(m.pending, &errs)
	expiredFailed := m.teardown(m.table.expired(m.ttl), &errs)
	m.pending = append(retryFailed, expiredFailed...)

	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

func (m *IPMapper) teardown(items []pair, errs *[]error) (failed []pair) {
	for _, p := range items {
		if delErr := m.fw.Delete(firewall.Mapping{Fake: utils.Uint32ToIP(p.fake), Real: utils.Uint32ToIP(p.real)}); delErr != nil {
			*errs = append(*errs, delErr)
			failed = append(failed, p)
			continue
		}
		m.pool.release(p.fake)
	}
	return
}

func (m *IPMapper) GetTTL() time.Duration {
	return m.ttl
}
