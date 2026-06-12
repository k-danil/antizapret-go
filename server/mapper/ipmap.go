package mapper

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/k-danil/antizapret-go/utils"
)

type nftProgrammer interface {
	Add(fakeIP, realIP net.IP, comment string) error
	Delete(fakeIP, realIP net.IP) error
}

type IPMapper struct {
	used *utils.SafeTTLMap[uint32, uint32]
	free *utils.SafeQueue[uint32]

	ttl time.Duration

	nft nftProgrammer

	// allocMu сериализует холодные пути (аллокация в Map, teardown в Clean),
	// чтобы переаллокация real не пересекалась с его удалением.
	allocMu sync.Mutex
}

func NewIPMapper(cidr string, ttl time.Duration, nft nftProgrammer) (m *IPMapper, err error) {
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
		err = fmt.Errorf("failed to parse CIDR: %w", err)
		return
	}

	m = &IPMapper{
		used: utils.NewTTLMap[uint32, uint32](20000, ttl),
		free: utils.NewQueue[uint32](),
		ttl:  ttl,
		nft:  nft,
	}
	m.free.FillFromIter(utils.GetIPv4HostIterator(ipnet))

	return m, nil
}

func (m *IPMapper) Map(realIP net.IP, host string) (fakeIP net.IP, err error) {
	realUint := utils.IPToUint32(realIP)

	if fakeUint, ok := m.used.Get(realUint); ok {
		return utils.Uint32ToIP(fakeUint), nil
	}

	m.allocMu.Lock()
	defer m.allocMu.Unlock()

	if fakeUint, ok := m.used.Get(realUint); ok {
		return utils.Uint32ToIP(fakeUint), nil
	}

	fakeUint, ok := m.free.Dequeue()
	if !ok {
		err = fmt.Errorf("no free IPs")
		return
	}

	if err = m.nft.Add(utils.Uint32ToIP(fakeUint), realIP, fmt.Sprintf("host %s", host)); err != nil {
		m.free.EnqueueTail(fakeUint)
		return
	}

	m.used.Set(realUint, fakeUint)
	return utils.Uint32ToIP(fakeUint), nil
}

func (m *IPMapper) Clean() (err error) {
	m.allocMu.Lock()
	defer m.allocMu.Unlock()

	res := m.used.Clean()

	var errs []error
	for _, pair := range res {
		if err = m.nft.Delete(utils.Uint32ToIP(pair.Value), utils.Uint32ToIP(pair.Key)); err != nil {
			errs = append(errs, err)
			m.used.Set(pair.Key, pair.Value)
			continue
		}
		m.free.EnqueueTail(pair.Value)
	}
	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

func (m *IPMapper) GetTTL() time.Duration {
	return m.ttl
}
