package server

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/server/cache"
	"github.com/antizapret-vpn/go-proxy/server/mapper"
	"github.com/antizapret-vpn/go-proxy/server/nft"
	"github.com/antizapret-vpn/go-proxy/server/resolver"
	rtr "github.com/antizapret-vpn/go-proxy/server/router"
)

type Server struct {
	resolver   *resolver.Resolver
	ipMapper   *mapper.IPMapper
	nftManager *nft.Manager
	router     *rtr.Router
	cache      *cache.Cache

	timeout time.Duration
	ipv6    bool
}

func NewServer(cfg cfg.AntizapretConfig) (s *Server, err error) {
	s = new(Server)

	if s.nftManager, err = nft.NewNftManager(cfg.NFT.Chain, cfg.NFT.Set); err != nil {
		return
	}

	if s.ipMapper, err = mapper.NewIPMapper(cfg.FakeCIDR, cfg.NFT.TTL, s.nftManager); err != nil {
		return
	}

	if s.resolver, err = resolver.NewResolver(cfg.Upstreams); err != nil {
		return
	}

	s.cache = cache.NewCache(uint64(cfg.Cache.Capacity), cfg.Cache.TTL)

	s.router = rtr.NewRouter(cfg.Policy.Matchers)
	if err := s.router.Rebuild(context.Background()); err != nil {
		log.L.Errorw("failed to rebuild router", "err", err)
	}

	s.timeout = cfg.RequestTimeout

	return s, err
}

func (s *Server) PolicyRebuilder(ctx context.Context, interval time.Duration, reload <-chan os.Signal) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-reload:
			log.L.Infow("reloading router")
			if err := s.router.Rebuild(ctx); err != nil {
				log.L.Errorw("failed to rebuild router", "err", err)
			}
		case <-ticker.C:
			if err := s.router.Rebuild(ctx); err != nil {
				log.L.Errorw("failed to rebuild router", "err", err)
			}
		}
	}
}

func (s *Server) NFTCleaner(ctx context.Context, interval time.Duration) {
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

func (s *Server) Close() (err error) {
	var errS []error
	if err := s.cache.Close(); err != nil {
		errS = append(errS, err)
	}
	if err := s.nftManager.Close(); err != nil {
		errS = append(errS, err)
	}

	if len(errS) > 0 {
		err = errors.Join(errS...)
	}

	return
}
