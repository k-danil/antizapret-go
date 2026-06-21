package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace          = "antizapret"
	serverReadTimeout  = 5 * time.Second
	serverWriteTimeout = 10 * time.Second
	serverIdleTimeout  = 60 * time.Second
	shutdownGrace      = 5 * time.Second
)

const (
	ServedCache      = "cache"
	ServedUpstream   = "upstream"
	ServedSuppressed = "suppressed"
	ServedError      = "error"

	RcodeNoError  = "NOERROR"
	RcodeFormErr  = "FORMERR"
	RcodeServFail = "SERVFAIL"
	RcodeNXDomain = "NXDOMAIN"
	RcodeNotImp   = "NOTIMP"
	RcodeRefused  = "REFUSED"
	RcodeOther    = "other"

	ActionNone = "none"
)

type Metrics struct {
	registry *prometheus.Registry

	responses        *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	upstreamQueries  *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
	rebuilds         *prometheus.CounterVec
	rebuildDuration  prometheus.Histogram
}

func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		responses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "dns_responses_total",
			Help: "DNS-ответы по rcode и действию роутера.",
		}, []string{"rcode", "action"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "dns_request_duration_seconds",
			Help:    "Латентность обработки запроса по источнику ответа (cache/upstream/...).",
			Buckets: []float64{1e-6, 1e-5, 1e-4, 1e-3, 5e-3, 1e-2, 5e-2, 1e-1, 5e-1, 1, 2},
		}, []string{"served"}),
		upstreamQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "upstream_queries_total",
			Help: "Запросы к апстримам по имени и результату.",
		}, []string{"upstream", "result"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "upstream_query_duration_seconds",
			Help:    "Латентность запроса к апстриму.",
			Buckets: prometheus.DefBuckets,
		}, []string{"upstream"}),
		rebuilds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "router_rebuilds_total",
			Help: "Ребилды роутера по результату.",
		}, []string{"result"}),
		rebuildDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Name: "router_rebuild_duration_seconds",
			Help:    "Длительность ребилда роутера.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
		}),
	}

	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.responses, m.requestDuration, m.upstreamQueries, m.upstreamDuration,
		m.rebuilds, m.rebuildDuration,
	)
	return m
}

func (m *Metrics) Enabled() bool {
	return m != nil
}

// StateSource — состояние сервиса для gauge-метрик; методы зовутся на scrape.
type StateSource interface {
	Ready() bool
	ActiveMappings() int
	PoolCapacity() int
	CacheSize() int
}

func (m *Metrics) RegisterState(src StateSource) {
	m.registerGauge("ready", "1 — сервис готов (radix загружен), иначе 0.", func() float64 {
		if src.Ready() {
			return 1
		}
		return 0
	})
	m.registerGauge("mapper_active_mappings", "Активных маппингов fake→real.", func() float64 {
		return float64(src.ActiveMappings())
	})
	m.registerGauge("mapper_pool_capacity", "Ёмкость пула fake-IP.", func() float64 {
		return float64(src.PoolCapacity())
	})
	m.registerGauge("dns_cache_size", "Записей в DNS-кэше.", func() float64 {
		return float64(src.CacheSize())
	})
}

func (m *Metrics) registerGauge(name, help string, fn func() float64) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Name: name, Help: help,
	}, fn))
}

func (m *Metrics) ObserveUpstream(name string, err error, d time.Duration) {
	m.upstreamDuration.WithLabelValues(name).Observe(d.Seconds())
	m.upstreamQueries.WithLabelValues(name, resultLabel(err)).Inc()
}

func (m *Metrics) ObserveRebuild(err error, d time.Duration) {
	m.rebuildDuration.Observe(d.Seconds())
	m.rebuilds.WithLabelValues(resultLabel(err)).Inc()
}

func (m *Metrics) ObserveRequest(rcode, action, served string, d time.Duration) {
	m.responses.WithLabelValues(rcode, action).Inc()
	m.requestDuration.WithLabelValues(served).Observe(d.Seconds())
}

func (m *Metrics) Serve(ctx context.Context, addr, version string, ready func() bool) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready\n", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(version + "\n"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: serverReadTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func resultLabel(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}
