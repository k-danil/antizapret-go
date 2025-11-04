package server

import (
	"context"
	"time"

	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/server/mapper"
	"github.com/antizapret-vpn/go-proxy/server/nft"
)

type Server struct {
	ipMapper   *mapper.IPMapper
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
		ipMapper:   ipMapper,
		nftManager: nftManager,
	}
	s.DNS, err = NewDNSHandler(s, cfg.Upstream.Address, cfg.Upstream.Timeout, cfg.Cache.TTL)

	return s, err
}

func (s *Server) Cleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ipMapper.Clean(); err != nil {
				log.L.Errorw("cleaning failed", "err", err)
			}
		}
	}
}
