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
	hubupdate.StartAutoUpdater(6 * time.Hour)

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
