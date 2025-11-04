package mapper

import (
	"fmt"
	"net"
	"time"

	"github.com/antizapret-vpn/go-proxy/server/nft"
	"github.com/antizapret-vpn/go-proxy/utils"
)

type IPMapper struct {
	used *utils.SafeMap[uint32, uint32]
	free *utils.SafeQueue[uint32]

	nft *nft.Manager
}

func NewIPMapper(cidr string, capacity int, ttl time.Duration, nft *nft.Manager) (m *IPMapper, err error) {
	var ipnet *net.IPNet
	if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
		err = fmt.Errorf("failed to parse CIDR: %w", err)
		return
	}

	m = &IPMapper{
		used: utils.NewMap[uint32, uint32](capacity, ttl),
		free: utils.NewQueue[uint32](),
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
