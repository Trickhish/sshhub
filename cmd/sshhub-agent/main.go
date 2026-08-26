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
	backend := flag.String("backend", "", "optional backend id override")
	sshd := flag.String("sshd", "", "optional local sshd address to bridge to (if omitted, agent serves sessions natively)")
	useTLS := flag.Bool("tls", false, "connect to the hub over TLS")
	insecure := flag.Bool("tls-insecure-skip-verify", false, "skip TLS certificate verification")
	flag.Parse()

	if *hub == "" || *token == "" {
		log.Fatal("--hub and --token are required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tlsConfig *tls.Config
	if *useTLS {
		tlsConfig = &tls.Config{InsecureSkipVerify: *insecure} // #nosec G402 -- opt-in for self-signed certs
	}

	session, assignedBackend, err := control.Connect(ctx, *hub, *backend, *token, tlsConfig)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	log.Printf("registered backend %q with %s", assignedBackend, *hub)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
		session.Close()
	}()

	if *sshd != "" {
		log.Printf("bridging reverse streams to local sshd %s", *sshd)
		if err := control.Serve(ctx, session, *sshd); err != nil {
			log.Fatalf("serve sshd bridge: %v", err)
		}
	} else {
		log.Printf("serving native PTY sessions on agent")
		agentServer, err := control.NewAgentServer()
		if err != nil {
			log.Fatalf("create agent server: %v", err)
		}
		if err := agentServer.ServeStreams(ctx, session); err != nil {
			log.Fatalf("serve native sessions: %v", err)
		}
	}
}
