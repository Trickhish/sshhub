// Command sshhub-ctl manages backends, tokens, and updates for sshhub.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/hubupdate"
	"github.com/Trickhish/sshhub/internal/version"
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
			noRestart   = false
			id          = ""
		)

		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			switch {
			case arg == "--hub" && i+1 < len(os.Args):
				hubAddr = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--hub="):
				hubAddr = strings.TrimPrefix(arg, "--hub=")
			case arg == "--token" && i+1 < len(os.Args):
				customToken = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--token="):
				customToken = strings.TrimPrefix(arg, "--token=")
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
			log.Fatal("usage: sshhub-ctl add <backend-id> [--config <path>] [--hub <host:port>] [--token <custom-token>]")
		}

		token, err := config.AddBackend(cfgPath, id, customToken)
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

		fmt.Println()
		fmt.Printf("✓ Backend %q successfully registered in %s\n", id, cfgPath)
		fmt.Println()
		fmt.Println("Generated Token:")
		fmt.Printf("  %s\n", token)
		fmt.Println()
		fmt.Printf("1-Line Agent Install Command (run on node %q):\n", id)
		fmt.Printf("  curl -sSL %s | sudo bash -s -- --hub %s --token %q\n", repoRawURL, hub, token)
		fmt.Println()
		fmt.Printf("Manual binary command:\n")
		fmt.Printf("  sshhub-agent --hub %s --token %q\n", hub, token)
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
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--config" && i+1 < len(os.Args) {
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

		fmt.Printf("Backends configured in %s:\n\n", cfgPath)
		fmt.Printf("%-15s %-10s %-15s %s\n", "ID", "MODE", "ADDRESS", "TOKEN")
		fmt.Printf("%-15s %-10s %-15s %s\n", "---------------", "----------", "---------------", "------------------------------------------")
		for _, b := range cfg.Backends {
			addr := b.Address
			if addr == "" {
				addr = "-"
			}
			tok := b.Token
			if tok == "" {
				tok = "-"
			}
			fmt.Printf("%-15s %-10s %-15s %s\n", b.ID, b.Mode, addr, tok)
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
	fmt.Println("  list         List all configured backends and tokens")
	fmt.Println("  update       Check for and apply updates from GitHub Releases")
	fmt.Println("  version      Show current version")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sshhub-ctl add worker1")
	fmt.Println("  sshhub-ctl list")
	fmt.Println("  sshhub-ctl update")
	fmt.Println("  sshhub-ctl update --check")
	fmt.Println("  sshhub-ctl remove worker1")
}
