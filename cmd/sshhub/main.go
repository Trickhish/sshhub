// Command sshhub is the central SSH gateway.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/proxy"
)

func main() {
	configPath := flag.String("config", "sshhub.yaml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	registry := control.NewRegistry()

	controlServer := control.NewServer(
		registry,
		func(token, requestedBackend string) (string, bool) {
			// 1. Resolve by per-backend token
			if b := cfg.BackendByToken(token); b != nil {
				return b.ID, true
			}
			// 2. Check global control_tokens with requested backend
			if requestedBackend != "" && slices.Contains(cfg.ControlTokens, token) {
				if b := cfg.BackendByID(requestedBackend); b != nil && b.Mode == "reverse" {
					return b.ID, true
				}
			}
			return "", false
		},
		controlTLS(cfg),
	)

	proxyServer, err := proxy.New(cfg, registry)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := controlServer.ListenAndServe(ctx, cfg.Listen.Control); err != nil {
			log.Fatalf("control: %v", err)
		}
	}()
	go func() {
		if err := proxyServer.Serve(ctx, cfg.Listen.SSH); err != nil {
			log.Fatalf("ssh: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	cancel()
}

func controlTLS(cfg *config.Config) *tls.Config {
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
