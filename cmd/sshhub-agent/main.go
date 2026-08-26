// Command sshhub-agent connects a backend to the sshhub control plane.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Trickhish/sshhub/internal/control"
)

func main() {
	hub := flag.String("hub", "", "hub control address (host:port)")
	token := flag.String("token", "", "control plane token")
	backend := flag.String("backend", "", "backend id to register")
	sshd := flag.String("sshd", "127.0.0.1:22", "local sshd address to bridge to")
	useTLS := flag.Bool("tls", false, "connect to the hub over TLS")
	insecure := flag.Bool("tls-insecure-skip-verify", false, "skip TLS certificate verification")
	flag.Parse()

	if *hub == "" || *token == "" || *backend == "" {
		log.Fatal("--hub, --token, and --backend are required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tlsConfig *tls.Config
	if *useTLS {
		tlsConfig = &tls.Config{InsecureSkipVerify: *insecure} // #nosec G402 -- opt-in for self-signed certs
	}

	session, err := control.Connect(ctx, *hub, *backend, *token, tlsConfig)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	log.Printf("registered backend %q with %s", *backend, *hub)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
		session.Close()
	}()

	if err := control.Serve(ctx, session, *sshd); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
