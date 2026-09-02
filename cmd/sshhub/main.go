// Command sshhub is the central SSH gateway.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/Trickhish/sshhub/internal/admin"
	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
	"github.com/Trickhish/sshhub/internal/hubupdate"
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

	// Start background auto-updater for the Hub gateway
	wait := cfg.ResolvedAutoUpdateWait()
	switch {
	case wait == config.AutoUpdateDisabled:
		log.Printf("auto-update: DISABLED (auto_update_wait: false); update manually with 'sshhub-ctl update'")
	case wait == 0:
		log.Printf("auto-update: releases install as soon as they appear (auto_update_wait: 0)")
	default:
		log.Printf("auto-update: releases install once %s old (auto_update_wait)", wait)
	}
	hubupdate.StartAutoUpdater(6*time.Hour, wait)

	// Local read-only status socket for sshhub-ctl. Failure here is not fatal:
	// losing operator visibility should not take the gateway down.
	adminSrv := admin.NewServer(registry)
	go func() {
		if err := adminSrv.ListenAndServe(ctx, admin.DefaultSocketPath); err != nil {
			log.Printf("admin socket unavailable: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	cancel()
}

// controlTLS returns the TLS configuration for the control listener.
//
// TLS is ALWAYS enabled. The control plane carries agent registration tokens,
// which are an agent's only credential; it previously defaulted to plaintext on
// a public port, so anyone on-path could capture a token and register as that
// backend. If no certificate is configured a self-signed one is generated and
// persisted, and agents authenticate the hub by public key pin.
func controlTLS(cfg *config.Config) *tls.Config {
	certPath, keyPath := cfg.TLSCert, cfg.TLSKey
	if certPath == "" || keyPath == "" {
		certPath = config.DefaultTLSCertPath
		keyPath = config.DefaultTLSKeyPath
		log.Printf("tls: no certificate configured; using self-signed at %s", certPath)
	}

	var hosts []string
	if cfg.PublicHost != "" {
		host := cfg.PublicHost
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		hosts = append(hosts, host)
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}

	cert, err := hubtls.LoadOrCreate(certPath, keyPath, hosts)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		log.Printf("control plane key pin: %s", hubtls.Fingerprint(leaf))
	}

	return hubtls.ServerConfig(cert)
}
