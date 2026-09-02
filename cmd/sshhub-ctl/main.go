// Command sshhub-ctl manages backends, tokens, and updates for sshhub.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"encoding/json"
	"github.com/Trickhish/sshhub/internal/admin"
	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
	"github.com/Trickhish/sshhub/internal/hubupdate"
	"github.com/Trickhish/sshhub/internal/version"
	"time"
)

const repoRawURL = "https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "add":
		var (
			cfgPath     = defaultConfigPath()
			hubAddr     = ""
			customToken = ""
			endUser     = ""
			noRestart   = false
			id          = ""
		)

		// NOTE: the increment must happen on the loop variable, not inside the
		// switch arm; a bare `i++` in a case is shadowed by the loop's own i++
		// and the flag's value would be misread as the backend id.
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			next := ""
			hasNext := i+1 < len(os.Args)
			if hasNext {
				next = os.Args[i+1]
			}

			switch {
			case arg == "--hub" && hasNext:
				hubAddr = next
				i++
			case strings.HasPrefix(arg, "--hub="):
				hubAddr = strings.TrimPrefix(arg, "--hub=")
			case arg == "--token" && hasNext:
				customToken = next
				i++
			case strings.HasPrefix(arg, "--token="):
				customToken = strings.TrimPrefix(arg, "--token=")
			case arg == "--end-user" && hasNext:
				endUser = next
				i++
			case strings.HasPrefix(arg, "--end-user="):
				endUser = strings.TrimPrefix(arg, "--end-user=")
			case arg == "--config" && hasNext:
				cfgPath = next
				i++
			case strings.HasPrefix(arg, "--config="):
				cfgPath = strings.TrimPrefix(arg, "--config=")
			case arg == "--no-restart":
				noRestart = true
			case !strings.HasPrefix(arg, "-") && id == "":
				id = arg
			}
		}

		if id == "" {
			log.Fatal("usage: sshhub-ctl add <backend-id> [--config <path>] [--hub <host:port>] " +
				"[--token <custom-token>] [--end-user <unix-user>]")
		}

		token, err := config.AddBackend(cfgPath, id, customToken, endUser)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		if !noRestart {
			_ = exec.Command("systemctl", "try-restart", "sshhub").Run()
		}

		hub := hubAddr
		if hub == "" {
			if cfg, err := config.Load(cfgPath); err == nil {
				if cfg.PublicHost != "" {
					if strings.Contains(cfg.PublicHost, ":") {
						hub = cfg.PublicHost
					} else {
						port := "7000"
						if cfg.Listen.Control != "" {
							if _, p, err := net.SplitHostPort(cfg.Listen.Control); err == nil {
								port = p
							} else if strings.HasPrefix(cfg.Listen.Control, ":") {
								port = strings.TrimPrefix(cfg.Listen.Control, ":")
							}
						}
						hub = net.JoinHostPort(cfg.PublicHost, port)
					}
				} else if cfg.Listen.Control != "" {
					control := cfg.Listen.Control
					if strings.HasPrefix(control, ":") {
						host := getFQDN()
						hub = host + control
					} else {
						hub = control
					}
				}
			}
		}
		if hub == "" {
			hub = "<hub-host>:7000"
		}

		domain := "<hub-domain>"
		if hub != "" && hub != "<hub-host>:7000" {
			if h, _, err := net.SplitHostPort(hub); err == nil {
				domain = h
			} else {
				domain = hub
			}
		}

		// The agent must pin the hub's key, otherwise its token is exposed to
		// anyone on-path. Surface the pin here so the install command is
		// complete and correct by construction.
		pin := controlPlanePin(cfgPath)

		fmt.Println()
		fmt.Printf("✓ Backend %q successfully registered in %s\n", id, cfgPath)
		fmt.Println()
		fmt.Println("Generated Token:")
		fmt.Printf("  %s\n", token)
		fmt.Println()
		fmt.Println("Hub Key Pin:")
		fmt.Printf("  %s\n", pin)
		fmt.Println()
		fmt.Printf("1-Line Agent Install Command (run on node %q):\n", id)
		fmt.Printf("  curl -sSL %s | sudo bash -s -- --hub %s --token %q --hub-pin %q\n",
			repoRawURL, hub, token, pin)
		fmt.Println()
		fmt.Printf("Manual binary command:\n")
		fmt.Printf("  sshhub-agent --hub %s --token %q --hub-pin %q\n", hub, token, pin)
		fmt.Println()
		fmt.Println("To connect from your client:")
		fmt.Printf("  ssh %s@%s\n", id, domain)
		fmt.Printf("  ssh root@%s@%s\n", id, domain)
		fmt.Println()

	case "remove", "rm":
		cfgPath := defaultConfigPath()
		noRestart := false
		id := ""

		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			switch {
			case arg == "--config" && i+1 < len(os.Args):
				cfgPath = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--config="):
				cfgPath = strings.TrimPrefix(arg, "--config=")
			case arg == "--no-restart":
				noRestart = true
			case !strings.HasPrefix(arg, "-") && id == "":
				id = arg
			}
		}

		if id == "" {
			log.Fatal("usage: sshhub-ctl remove <backend-id> [--config <path>]")
		}

		if err := config.RemoveBackend(cfgPath, id); err != nil {
			log.Fatalf("error: %v", err)
		}
		if !noRestart {
			_ = exec.Command("systemctl", "try-restart", "sshhub").Run()
		}
		fmt.Printf("✓ Backend %q removed from %s\n", id, cfgPath)

	case "list", "ls":
		cfgPath := defaultConfigPath()
		jsonOut := false
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--json" {
				jsonOut = true
			} else if arg == "--config" && i+1 < len(os.Args) {
				cfgPath = os.Args[i+1]
				i++
			} else if strings.HasPrefix(arg, "--config=") {
				cfgPath = strings.TrimPrefix(arg, "--config=")
			}
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}

		// Collect the end users each backend is reachable as, so the operator can
		// see at a glance which nodes have routes granting root.
		endUsers := make(map[string][]string)
		for _, r := range cfg.Routes {
			u := r.ResolvedEndUser()
			for _, existing := range endUsers[r.Backend] {
				if existing == u {
					u = ""
					break
				}
			}
			if u != "" {
				endUsers[r.Backend] = append(endUsers[r.Backend], u)
			}
		}

		// Live state comes from the hub's admin socket; the config file alone
		// cannot know what is connected. If the socket is unavailable (hub not
		// running, or an older hub without it) fall back to config-only output
		// rather than failing, and say so.
		var status *admin.Status
		var statusErr error
		if st, err := admin.Query(admin.DefaultSocketPath); err == nil {
			status = st
		} else {
			statusErr = err
		}

		live := map[string]control.BackendStatus{}
		if status != nil {
			for _, b := range status.Backends {
				live[b.Backend] = b
			}
		}

		if jsonOut {
			type row struct {
				ID       string   `json:"id"`
				EndUsers []string `json:"end_users"`
				Online   bool     `json:"online"`
				Version  string   `json:"version,omitempty"`
				Platform string   `json:"platform,omitempty"`
				Uptime   string   `json:"connected_for,omitempty"`
				Remote   string   `json:"remote_addr,omitempty"`
			}
			rows := make([]row, 0, len(cfg.Backends))
			for _, b := range cfg.Backends {
				r := row{ID: b.ID, EndUsers: endUsers[b.ID]}
				if l, ok := live[b.ID]; ok {
					r.Online, r.Version, r.Remote = true, l.Version, l.RemoteAddr
					if l.OS != "" {
						r.Platform = l.OS + "/" + l.Arch
					}
					r.Uptime = shortDuration(time.Since(l.ConnectedAt))
				}
				rows = append(rows, r)
			}
			out, _ := json.MarshalIndent(rows, "", "  ")
			fmt.Println(string(out))
			return
		}

		fmt.Printf("Backends configured in %s:\n\n", cfgPath)
		fmt.Printf("%-14s %-9s %-9s %-14s %-11s %s\n",
			"ID", "STATUS", "VERSION", "PLATFORM", "CONNECTED", "END USERS")
		fmt.Printf("%-14s %-9s %-9s %-14s %-11s %s\n",
			"--------------", "---------", "---------", "--------------", "-----------", "----------")

		var online int
		for _, b := range cfg.Backends {
			users := "-"
			if u := endUsers[b.ID]; len(u) > 0 {
				users = strings.Join(u, ",")
			}

			st, ver, plat, up := "offline", "-", "-", "-"
			if l, ok := live[b.ID]; ok {
				online++
				st = "online"
				if l.Version != "" {
					ver = l.Version
				}
				if l.OS != "" {
					plat = l.OS + "/" + l.Arch
				}
				up = shortDuration(time.Since(l.ConnectedAt))
			} else if status == nil {
				st = "unknown"
			}

			fmt.Printf("%-14s %-9s %-9s %-14s %-11s %s\n", b.ID, st, ver, plat, up, users)
		}

		fmt.Println()
		if status != nil {
			fmt.Printf("%d/%d online. Hub %s, up %s.\n",
				online, len(cfg.Backends), status.HubVersion, shortDuration(time.Since(status.StartedAt)))
			var stale []string
			for _, b := range cfg.Backends {
				if l, ok := live[b.ID]; ok && l.Version != "" && l.Version != status.HubVersion {
					stale = append(stale, fmt.Sprintf("%s (%s)", b.ID, l.Version))
				}
			}
			if len(stale) > 0 {
				fmt.Printf("Agents not on %s: %s\n", status.HubVersion, strings.Join(stale, ", "))
			}
		} else {
			fmt.Printf("Live status unavailable (%v).\n", statusErr)
			fmt.Println("Showing configuration only; run on the hub host as root for agent status.")
		}
		fmt.Println()

	case "update", "upgrade":
		targetVersion := ""
		checkOnly := false
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			switch {
			case arg == "--check":
				checkOnly = true
			case arg == "--version" && i+1 < len(os.Args):
				targetVersion = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--version="):
				targetVersion = strings.TrimPrefix(arg, "--version=")
			}
		}

		fmt.Printf("Current version: %s\n", version.Version)
		fmt.Print("Checking for updates on GitHub... ")
		latest, err := hubupdate.FetchLatestVersion()
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("latest release is %s\n", latest)

		if !hubupdate.IsNewer(latest, version.Version) && targetVersion == "" {
			fmt.Println("✓ SSHub Gateway is already up to date!")
			return
		}

		if checkOnly {
			fmt.Printf("Update available: %s -> %s\n", version.Version, latest)
			return
		}

		verToInstall := latest
		if targetVersion != "" {
			verToInstall = targetVersion
		}

		fmt.Printf("Downloading and applying %s from GitHub...\n", verToInstall)
		if err := hubupdate.DownloadAndApplyHubUpdate(verToInstall); err != nil {
			log.Fatalf("update failed: %v", err)
		}

		fmt.Println("Restarting sshhub service...")
		_ = exec.Command("systemctl", "try-restart", "sshhub").Run()
		fmt.Printf("✓ SSHub Gateway successfully updated to %s!\n", verToInstall)

	case "pin":
		cfgPath := defaultConfigPath()
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--config" && i+1 < len(os.Args) {
				cfgPath = os.Args[i+1]
				i++
			} else if strings.HasPrefix(os.Args[i], "--config=") {
				cfgPath = strings.TrimPrefix(os.Args[i], "--config=")
			}
		}
		fmt.Println(controlPlanePin(cfgPath))

	case "version", "-v", "--version":
		fmt.Printf("sshhub version %s\n", version.Version)

	default:
		printUsage()
		os.Exit(1)
	}
}

func getFQDN() string {
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		fqdn := strings.TrimSpace(string(out))
		if fqdn != "" {
			return fqdn
		}
	}
	h, _ := os.Hostname()
	return h
}

func defaultConfigPath() string {
	const standard = "/etc/sshhub/sshhub.yaml"
	if _, err := os.Stat(standard); err == nil {
		return standard
	}
	if _, err := os.Stat("sshhub.yaml"); err == nil {
		return "sshhub.yaml"
	}
	return standard
}

func printUsage() {
	fmt.Println("Usage: sshhub-ctl <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  add <id>     Add a new reverse backend, generate token, and update config")
	fmt.Println("  remove <id>  Remove a backend and its routes from config")
	fmt.Println("  list         Show backends with agent status, version, and uptime")
	fmt.Println("  list --json  Same, as JSON for scripting")
	fmt.Println("  pin          Show the hub key pin agents must use (--hub-pin)")
	fmt.Println("  update       Check for and apply updates from GitHub Releases")
	fmt.Println("  version      Show current version")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sshhub-ctl add worker1")
	fmt.Println("  sshhub-ctl add worker1 --end-user deploy")
	fmt.Println("  sshhub-ctl pin")
	fmt.Println("  sshhub-ctl list")
	fmt.Println("  sshhub-ctl update")
	fmt.Println("  sshhub-ctl update --check")
	fmt.Println("  sshhub-ctl remove worker1")
}

// controlPlanePin returns the hub's control-plane public key pin, which agents
// need in order to authenticate the hub. Returns a placeholder if the
// certificate is not present yet (the hub generates it on first start).
func controlPlanePin(cfgPath string) string {
	certPath := config.DefaultTLSCertPath
	if cfg, err := config.Load(cfgPath); err == nil && cfg.TLSCert != "" {
		certPath = cfg.TLSCert
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		return "<start the hub once to generate its certificate, then run: sshhub-ctl pin>"
	}
	pin, err := hubtls.FingerprintFromPEM(data)
	if err != nil {
		return "<unreadable certificate: " + err.Error() + ">"
	}
	return pin
}

// shortDuration renders a duration for operator output: "3d4h", "2h14m", "45s".
// Go's default String() gives "2h14m32.19s", which is noise in a table.
func shortDuration(d time.Duration) string {
	if d < 0 {
		return "-"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
