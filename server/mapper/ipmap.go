package mapper

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/antizapret-vpn/go-proxy/server/nft"
	"github.com/antizapret-vpn/go-proxy/utils"
)

type IPMapper struct {
	used *utils.SafeTTLMap[uint32, uint32]
	free *utils.SafeQueue[uint32]

	ttl time.Duration

	nft *nft.Manager
}

func NewIPMapper(cidr string, ttl time.Duration, nft *nft.Manager) (m *IPMapper, err error) {
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

func (m *IPMapper) Map(real net.IP, host string) (net.IP, error) {
	realUint := utils.IPToUint32(real)
	fakeUint, ok := m.used.Get(realUint)
	if ok {
		return utils.Uint32ToIP(fakeUint), nil
	}
	fakeUint, ok = m.free.Dequeue()
	if !ok {
		return nil, fmt.Errorf("no free IPs")
	}
	m.used.Set(realUint, fakeUint)
	if err := m.nft.Add(real, utils.Uint32ToIP(fakeUint), fmt.Sprintf("host %s", host)); err != nil {
		return nil, err
	}
	return utils.Uint32ToIP(fakeUint), nil
}

func (m *IPMapper) Clean() (err error) {
	res := m.used.Clean()

	var errs []error
	for _, pair := range res {
		if err = m.nft.Delete(utils.Uint32ToIP(pair.Key), utils.Uint32ToIP(pair.Value)); err != nil {
			errs = append(errs, err)
		}
		m.free.EnqueueHead(pair.Value)
	}
	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

func (m *IPMapper) GetTTL() time.Duration {
	return m.ttl
}
