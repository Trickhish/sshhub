// Command sshhub-agent connects a backend to the sshhub control plane.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
)

func main() {
	hub := flag.String("hub", "", "hub control address (host:port)")
	token := flag.String("token", "", "control plane token")
	backend := flag.String("backend", "", "optional backend id override")
	sshd := flag.String("sshd", "", "optional local sshd address to bridge to (if omitted, agent serves sessions natively)")
	pin := flag.String("hub-pin", "", "hub public key pin (sha256:...) shown by 'sshhub-ctl add'")
	insecure := flag.Bool("insecure-no-pin", false,
		"connect without verifying the hub's identity (TESTING ONLY: exposes the token to interception)")
	flag.Parse()

	if *hub == "" || *token == "" {
		log.Fatal("--hub and --token are required")
	}

	// The connection carries the registration token, which is this agent's only
	// credential. Without a pin (or a CA-issued hub certificate) an on-path
	// attacker can capture it, so refuse rather than fall back to plaintext.
	if *pin == "" && !*insecure {
		log.Fatal("--hub-pin is required: the control connection carries your token, " +
			"and without a pin an on-path attacker could capture it. " +
			"Run 'sshhub-ctl add' on the hub to get the pin, or pass --insecure-no-pin for local testing.")
	}
	if *insecure {
		log.Print("WARNING: --insecure-no-pin: the hub is NOT authenticated and your token is exposed to interception")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverName := *hub
	if h, _, err := net.SplitHostPort(*hub); err == nil {
		serverName = h
	}

	var tlsConfig *tls.Config
	if *insecure {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit opt-in, warned above
	} else {
		cfg, err := hubtls.ClientConfig(serverName, *pin)
		if err != nil {
			log.Fatalf("hub pin: %v", err)
		}
		tlsConfig = cfg
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
