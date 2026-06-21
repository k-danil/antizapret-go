package server

import (
	"context"
	"errors"
	"os"
	"runtime/debug"
	"time"

	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/metrics"
	"github.com/k-danil/antizapret-go/server/cache"
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/mapper"
	"github.com/k-danil/antizapret-go/server/resolver"
	rtr "github.com/k-danil/antizapret-go/server/router"
)

type Server struct {
	resolver    *resolver.Resolver
	ipMapper    *mapper.IPMapper
	fw          firewall.Manager
	router      *rtr.Router
	routerStore *rtr.Store
	cache       *cache.Cache

	timeout        time.Duration
	rebuildTimeout time.Duration
	warm           bool
	rebuildReady   chan struct{}

	metrics *metrics.Metrics
}

func NewServer(cfg cfg.AntizapretConfig, fw firewall.Manager, m *metrics.Metrics) (s *Server, err error) {
	s = new(Server)
	s.fw = fw
	s.metrics = m

	if s.ipMapper, err = mapper.NewIPMapper(cfg.FakeCIDR, cfg.Firewall.TTL, s.fw); err != nil {
		return
	}

	if s.resolver, err = resolver.NewResolver(cfg.Upstreams, s.metrics); err != nil {
		return
	}

	s.cache = cache.NewCache(uint64(cfg.Cache.Capacity), cfg.Cache.TTL, cfg.Cache.MinTTL, cfg.Cache.MaxTTL)

	if s.routerStore, err = rtr.NewStore(cfg.StatePath); err != nil {
		return
	}

	if s.router, err = rtr.NewRouter(cfg.Policy.Matchers, s.routerStore); err != nil {
		return
	}

	s.warm = s.router.LoadCached() > 0
	s.rebuildReady = make(chan struct{})
	s.rebuildTimeout = cfg.Policy.RebuildTimeout
	s.timeout = cfg.RequestTimeout

	if m.Enabled() {
		m.RegisterState(s)
	}
	return s, err
}

func (s *Server) PolicyRebuilder(ctx context.Context, interval time.Duration, reload <-chan os.Signal) {
	s.rebuild(ctx)
	close(s.rebuildReady) // разблокирует WaitReady на холодном старте

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-reload:
			log.L.Infow("reloading router")
			s.rebuild(ctx)
		case <-ticker.C:
			s.rebuild(ctx)
		}
	}
}

func (s *Server) rebuild(ctx context.Context) {
	var err error
	if s.metrics.Enabled() {
		defer func(now time.Time) {
			s.metrics.ObserveRebuild(err, time.Since(now))
		}(time.Now())
	}

	rctx, cancel := context.WithTimeout(ctx, s.rebuildTimeout)
	defer cancel()
	if err = s.router.Rebuild(rctx); err != nil {
		log.L.Errorw("failed to rebuild router", "err", err)
	}

	// Rebuild оставляет мёртвыми старое дерево и парс-скрэтч (пик ~2.3×); сразу
	// возвращаем страницы ОС — иначе scavenger тянет это медленно и RSS висит на пике.
	debug.FreeOSMemory()
}

// WaitReady блокирует выдачу на холодном старте до первого rebuild (bounded его
// таймаутом, отменяемо через ctx). Тёплый старт обслуживает из кэша сразу.
func (s *Server) WaitReady(ctx context.Context) {
	if s.warm {
		return
	}
	select {
	case <-s.rebuildReady:
	case <-ctx.Done():
	}
}

func (s *Server) Ready() bool {
	return s.router.Ready()
}

func (s *Server) ActiveMappings() int {
	active, _ := s.ipMapper.Stats()
	return active
}

func (s *Server) PoolCapacity() int {
	_, capacity := s.ipMapper.Stats()
	return capacity
}

func (s *Server) CacheSize() int {
	return s.cache.Len()
}

func (s *Server) MappingCleaner(ctx context.Context, interval time.Duration) {
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
	if err := s.fw.Close(); err != nil {
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
