package server

import (
	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/server/mapper"
	"github.com/antizapret-vpn/go-proxy/server/nft"
)

type Server struct {
	Mapper     *mapper.IPMapper
	nftManager *nft.Manager
	DNS        *DNSHandler
}

func NewServer(cfg cfg.AntizapretConfig) (s *Server, err error) {
	var nftManager *nft.Manager
	if nftManager, err = nft.NewNftManager(cfg.Nft.Chain, cfg.Nft.Set); err != nil {
		return nil, err
	}

	var ipMapper *mapper.IPMapper
	if ipMapper, err = mapper.NewIPMapper(cfg.FakeCIDR, cfg.Cache.Capacity, cfg.Cache.TTL, nftManager); err != nil {
		return nil, err
	}
	s = &Server{
		Mapper:     ipMapper,
		nftManager: nftManager,
	}
	s.DNS, err = NewDNSHandler(s, cfg.Upstream.Address, cfg.Upstream.Timeout, cfg.Cache.TTL)

	return s, err

}
