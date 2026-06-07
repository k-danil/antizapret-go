package server

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/server/cache"
	"github.com/antizapret-vpn/go-proxy/server/mapper"
	"github.com/antizapret-vpn/go-proxy/server/resolver"
	rtr "github.com/antizapret-vpn/go-proxy/server/router"
)

// NFTManager — то, что серверу нужно от nft-слоя; инъектируется снаружи, чтобы
// пакет server не зависел от Linux-only nftables на этапе компиляции.
type NFTManager interface {
	Add(fakeIP, realIP net.IP, comment string) error
	Delete(fakeIP, realIP net.IP) error
	Close() error
}

type Server struct {
	resolver    *resolver.Resolver
	ipMapper    *mapper.IPMapper
	nftManager  NFTManager
	router      *rtr.Router
	routerStore *rtr.Store
	cache       *cache.Cache

	timeout time.Duration
}

func NewServer(cfg cfg.AntizapretConfig, nftManager NFTManager) (s *Server, err error) {
	s = new(Server)
	s.nftManager = nftManager

	if s.ipMapper, err = mapper.NewIPMapper(cfg.FakeCIDR, cfg.NFT.TTL, s.nftManager); err != nil {
		return
	}

	if s.resolver, err = resolver.NewResolver(cfg.Upstreams); err != nil {
		return
	}

	s.cache = cache.NewCache(uint64(cfg.Cache.Capacity), cfg.Cache.TTL, cfg.Cache.MinTTL, cfg.Cache.MaxTTL)

	if s.routerStore, err = rtr.NewStore(cfg.StatePath); err != nil {
		return
	}

	if s.router, err = rtr.NewRouter(cfg.Policy.Matchers, s.routerStore); err != nil {
		return
	}

	if s.router.LoadCached() == 0 {
		if rebuildErr := s.router.Rebuild(context.Background()); rebuildErr != nil {
			log.L.Errorw("initial router rebuild failed", "err", rebuildErr)
		}
	} else {
		go func() {
			if rebuildErr := s.router.Rebuild(context.Background()); rebuildErr != nil {
				log.L.Errorw("background router refresh failed", "err", rebuildErr)
			}
		}()
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
	if s.routerStore != nil {
		if err := s.routerStore.Close(); err != nil {
			errS = append(errS, err)
		}
	}

	if len(errS) > 0 {
		err = errors.Join(errS...)
	}

	return
}
