package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/server"
	"github.com/antizapret-vpn/go-proxy/server/nft"
)

const shutdownTimeout = 5 * time.Second

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

	nftManager, err := nft.NewNftManager(cfg.Antizapret.NFT.Chain, cfg.Antizapret.NFT.Set)
	if err != nil {
		log.L.Fatalw("Error creating nft manager",
			"err", err)
	}

	srv, err := server.NewServer(cfg.Antizapret, nftManager)
	if err != nil {
		log.L.Fatalw("Error creating server",
			"err", err)
	}
	defer func() { _ = srv.Close() }()

	go srv.NFTCleaner(ctx, cfg.Antizapret.NFT.TTL)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		defer signal.Stop(sig)
		srv.PolicyRebuilder(ctx, cfg.Antizapret.Policy.ReloadInterval, sig)
	}()

	dns.HandleFunc(".", srv.DNSHandler)

	var servers []*dns.Server
	for _, u := range cfg.Antizapret.Bindings {
		addr := fmt.Sprintf("%s:%d", u.Address, u.Port)
		protocol := u.Protocol
		if u.Address == "" || u.Address == "0.0.0.0" || u.Address == "::" {
			log.L.Warnw("DNS server bound to wildcard address; ensure it is not an open resolver",
				"address", addr, "protocol", protocol)
		}
		dnsServer := &dns.Server{Addr: addr, Net: protocol, ReusePort: true, MaxTCPQueries: -1}
		go func() {
			if err := dnsServer.ListenAndServe(); err != nil {
				log.L.Errorw("Error starting DNS server", "addr", addr, "protocol", protocol, "err", err)
				cancel()
			}
		}()
		servers = append(servers, dnsServer)
	}

	<-ctx.Done()
	log.L.Infow("Shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	for _, dnsServer := range servers {
		dnsServer.Shutdown(shutdownCtx)
	}
}
