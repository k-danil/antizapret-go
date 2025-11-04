package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/miekg/dns"
	"github.com/antizapret-vpn/go-proxy/cfg"
	"github.com/antizapret-vpn/go-proxy/log"
	"github.com/antizapret-vpn/go-proxy/server"
)

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

	_ = log.SetSeverity(cfg.Antizapret.LoggingSeverity)
	defer log.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := server.NewServer(cfg.Antizapret)
	if err != nil {
		log.L.Fatalw("Error creating server",
			"err", err)
	}

	dns.HandleFunc(".", srv.DNS.DNSHandler)

	addr := fmt.Sprintf("%s:%d", cfg.Antizapret.Listen.Address, cfg.Antizapret.Listen.Port)
	dnsServer := &dns.Server{Addr: addr, Net: cfg.Antizapret.Listen.Protocol, ReusePort: true, MaxTCPQueries: -1}
	go func() {
		if err = dnsServer.ListenAndServe(); err != nil {
			log.L.Fatalw("Error starting DNS server", "err", err)
		}
	}()
	<-ctx.Done()
	log.L.Infow("Shutting down")
	dnsServer.Shutdown(ctx)
}
