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
	"time"

	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
)

func main() {
	hub := flag.String("hub", "", "hub control address (host:port)")
	token := flag.String("token", "", "control plane token")
	backend := flag.String("backend", "", "optional backend id override")
	sshd := flag.String("sshd", "", "optional local sshd address to bridge to (if omitted, agent serves sessions natively)")
	hostKeyPath := flag.String("host-key", control.DefaultHostKeyPath,
		"path to the agent's persistent SSH host key")
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

	// Create the agent server first so its persistent host key can be advertised
	// at registration for the hub to pin.
	agentServer, err := control.NewAgentServerWithHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("agent host key: %v", err)
	}

	// Independent update check, in addition to the hub telling us at
	// registration. The registration path only fires when the HUB restarts, so
	// on its own it would leave agents stale if the hub stopped updating.
	control.StartAgentAutoUpdater(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("shutting down")
		cancel()
	}()

	run(ctx, cancel, agentServer, tlsConfig, *hub, *backend, *token, *sshd)
}

// run keeps the agent connected to the hub, reconnecting with backoff.
//
// The agent previously exited on any connection or serving error and relied on
// systemd's Restart=always to bring it back. That works, but it makes normal,
// expected conditions -- a hub restart, a brief network partition -- into
// process crashes, and it means the agent only survives where the supervisor is
// configured correctly. A hub that is down for maintenance should not require
// the supervisor to paper over it.
func run(ctx context.Context, cancel context.CancelFunc, agentServer *control.AgentServer,
	tlsConfig *tls.Config, hub, backend, token, sshd string) {

	const (
		minBackoff = 2 * time.Second
		maxBackoff = 60 * time.Second
	)
	backoff := minBackoff
	loggedDown := false

	for {
		if ctx.Err() != nil {
			return
		}

		session, assigned, err := control.ConnectWithHostKey(
			ctx, hub, backend, token, agentServer.HostKey(), tlsConfig)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Log the first failure at full volume, then stay quiet while the
			// hub is down so an outage does not fill the journal.
			if !loggedDown {
				log.Printf("cannot reach hub %s: %v (retrying every %s until it returns)", hub, err, backoff)
				loggedDown = true
			}
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("registered backend %q with %s", assigned, hub)
		backoff = minBackoff
		loggedDown = false

		// Serve until the tunnel drops, then reconnect.
		if sshd != "" {
			err = control.Serve(ctx, session, sshd)
		} else {
			err = agentServer.ServeStreams(ctx, session)
		}
		session.Close()

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("connection to hub lost: %v; reconnecting", err)
		} else {
			log.Print("connection to hub closed; reconnecting")
		}

		if !sleepCtx(ctx, minBackoff) {
			return
		}
	}
}

// sleepCtx waits for d, returning false if the context is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
