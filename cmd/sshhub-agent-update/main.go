// Command sshhub-agent-update installs a newer, signature-verified sshhub-agent.
//
// It runs as a short-lived root oneshot from a systemd timer, NOT inside the
// network-facing agent. That separation is the point:
//
//   - The agent stays unprivileged and sandboxed, so a flaw in the code parsing
//     attacker-controlled bytes cannot replace a binary.
//   - This updater is privileged but takes no input from the network peer, the
//     hub, or the agent. Its only input is the signed release manifest.
//   - Because it is a separate unit, it keeps running even when the agent is
//     broken or crash-looping, so a bad agent release can still be superseded
//     without hand-installing on every node. That recovery path is why the
//     updater must not live inside the thing it repairs.
//
// The version is resolved from GitHub directly. The hub never names a version:
// a compromised hub could otherwise pin agents to an older, known-vulnerable
// release (the rollback vector in the pre-0.7.0 updater, which also verified
// no signature at all).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Trickhish/sshhub/internal/hubupdate"
	"github.com/Trickhish/sshhub/internal/release"
	"github.com/Trickhish/sshhub/internal/version"
)

func main() {
	soak := flag.Duration("soak", 24*time.Hour,
		"how long a release must be public before installing it; 0 installs immediately")
	installer := flag.String("installer", "/usr/local/lib/sshhub/install-agent.sh",
		"path to the verified installer invoked to apply an update")
	dryRun := flag.Bool("dry-run", false, "report what would be installed, then exit")
	flag.Parse()

	// Fail closed: without a compiled-in trusted key this build cannot verify a
	// release, and an unverifiable update must never be installed automatically.
	if _, ok := release.TrustedKey(); !ok {
		log.Fatal("refusing to update: no trusted release key compiled in")
	}

	latest, published, err := hubupdate.FetchLatestRelease()
	if err != nil {
		log.Fatalf("cannot resolve latest release: %v", err)
	}
	if !hubupdate.IsNewer(latest, version.Version) {
		log.Printf("up to date (running %s, latest %s)", version.Version, latest)
		return
	}

	// Soak period. An update is how a bad release reaches every node unattended,
	// so a release must have been public long enough to be noticed and replaced.
	if *soak > 0 {
		if published.IsZero() {
			log.Printf("release %s has no publication time; deferring", latest)
			return
		}
		if age := time.Since(published); age < *soak {
			log.Printf("release %s is %s old; waiting until %s", latest, age.Round(time.Minute), *soak)
			return
		}
	}

	// Confirm the tag carries a valid signature BEFORE handing it to the
	// installer, so an unsigned or wrongly-signed release is rejected here.
	if _, err := hubupdate.LatestManifest(latest); err != nil {
		log.Fatalf("refusing update to %s: %v", latest, err)
	}

	if *dryRun {
		log.Printf("would install %s (running %s)", latest, version.Version)
		return
	}

	args, err := currentAgentArgs()
	if err != nil {
		log.Fatalf("cannot determine agent configuration: %v", err)
	}

	log.Printf("installing %s (running %s)", latest, version.Version)
	// The installer re-verifies the signature and artifact digest independently.
	cmd := exec.Command(*installer, append(args, "--version", latest)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("update to %s failed: %v", latest, err)
	}
	log.Printf("updated to %s", latest)
}

// currentAgentArgs recovers the agent's settings from its installed unit, so an
// update preserves them without this tool holding its own copy of the config.
//
// Only flags that are safe to reapply are carried over. The token is never read
// here; the installer reuses the token file already on disk.
func currentAgentArgs() ([]string, error) {
	out, err := exec.Command("systemctl", "show", "sshhub-agent", "-p", "ExecStart", "--value").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))

	var args []string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "--hub", "--hub-pin", "--sshd":
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("malformed ExecStart near %s", fields[i])
			}
			args = append(args, fields[i], fields[i+1])
			i++
		case "--token-file":
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("malformed ExecStart near %s", fields[i])
			}
			p := fields[i+1]
			// A systemd credentials path only exists inside the agent's own unit
			// sandbox, so point the installer at the durable file instead.
			if strings.Contains(p, "/credentials/") {
				p = "/etc/sshhub-agent/token"
			}
			args = append(args, "--token-file", p)
			i++
		}
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("no recognisable agent flags in ExecStart")
	}
	if _, err := os.Stat(filepath.Clean(args[len(args)-1])); err != nil && strings.Contains(strings.Join(args, " "), "--token-file") {
		// Non-fatal: the installer validates the token file itself and will
		// produce a clearer error than this pre-check can.
		log.Printf("warning: token file may be missing: %v", err)
	}
	return args, nil
}
