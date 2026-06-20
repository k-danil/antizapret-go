package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/k-danil/antizapret-go/cfg"
	"github.com/k-danil/antizapret-go/log"
	"github.com/k-danil/antizapret-go/server"
	"github.com/k-danil/antizapret-go/server/firewall"
	"github.com/k-danil/antizapret-go/server/firewall/iptables"
	"github.com/k-danil/antizapret-go/server/firewall/nft"
)

const (
	shutdownTimeout = 5 * time.Second
	edns0UDPSize    = 1232 // DNS flag day 2020
)

func newFirewall(c cfg.Firewall, fakeCIDR string) (firewall.Manager, error) {
	switch c.Backend {
	case cfg.BackendIPTables:
		return iptables.New(c.Chain, fakeCIDR)
	case cfg.BackendNFT, "":
		return nft.NewNftManager(c.Chain, c.Set)
	default:
		return nil, fmt.Errorf("unknown firewall backend `%s`", c.Backend)
	}
}

func main() {
	log.L.Infow("starting",
		"service", cfg.ServiceName,
		"version", cfg.ShowVersion())

	configFilename := flag.String("config", "", "Path to config file")
	help := flag.Bool("help", false, "Shows usage")
	defaultConfig := flag.Bool("default-config", false, "Print default config and exit")
	flag.Parse()

	if *defaultConfig {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "%s\n", cfg.AntizapretDefaultConfig)
		os.Exit(0)
	}

	if *help {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "%s\n", cfg.ShowVersion())
		flag.Usage()
		os.Exit(1)
	}

	if err := cfg.ReadConfig(*configFilename); err != nil {
		log.L.Fatalw("Error reading config",
			"configFilename", configFilename,
			"err", err)
	}

	if err := log.SetSeverity(cfg.Antizapret.LoggingSeverity); err != nil {
		log.L.Warnw("invalid logging_severity, using default",
			"value", cfg.Antizapret.LoggingSeverity, "err", err)
	}
	defer log.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	fw, err := newFirewall(cfg.Antizapret.Firewall, cfg.Antizapret.FakeCIDR)
	if err != nil {
		log.L.Fatalw("Error creating firewall backend",
			"err", err)
	}

	srv, err := server.NewServer(cfg.Antizapret, fw)
	if err != nil {
		log.L.Fatalw("Error creating server",
			"err", err)
	}
	defer func() { _ = srv.Close() }()

	go srv.NFTCleaner(ctx, cfg.Antizapret.Firewall.TTL)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		defer signal.Stop(sig)
		srv.PolicyRebuilder(ctx, cfg.Antizapret.Policy.ReloadInterval, sig)
	}()

	srv.WaitReady(ctx)

	dns.HandleFunc(".", srv.DNSHandler)

	processes := cfg.Antizapret.Processes
	if processes <= 0 {
		processes = runtime.NumCPU()
	}

	var servers []*dns.Server
	for _, u := range cfg.Antizapret.Bindings {
		addr := fmt.Sprintf("%s:%d", u.Address, u.Port)
		protocol := u.Protocol
		if u.Address == "" || u.Address == "0.0.0.0" || u.Address == "::" {
			log.L.Warnw("DNS server bound to wildcard address; ensure it is not an open resolver",
				"address", addr, "protocol", protocol)
		}
		// несколько листенеров на один адрес — иначе SO_REUSEPORT бессмыслен: с N сокетами
		// ядро раскидывает приём по ядрам (один сокет = один read-loop).
		for range processes {
			dnsServer := &dns.Server{Addr: addr, Net: protocol, ReusePort: true, UDPSize: edns0UDPSize}
			go func() {
				if err := dnsServer.ListenAndServe(); err != nil {
					log.L.Errorw("Error starting DNS server", "addr", addr, "protocol", protocol, "err", err)
					cancel()
				}
			}()
			servers = append(servers, dnsServer)
		}
	}
	log.L.Infow("DNS listeners started",
		"bindings", len(cfg.Antizapret.Bindings), "processes_per_binding", processes, "total", len(servers))

	<-ctx.Done()
	log.L.Infow("Shutting down")
	shutdownServers(servers)
}

// dns.Server.Shutdown блокируется до завершения in-flight, но переданный ctx игнорирует —
// поэтому общий бюджет ожидания дренажа держим сами.
func shutdownServers(servers []*dns.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, s := range servers {
			wg.Go(func() { s.Shutdown(ctx) })
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.L.Infow("all DNS listeners stopped")
	case <-ctx.Done():
		log.L.Warnw("DNS shutdown timed out; exiting", "timeout", shutdownTimeout)
	}
}
