// Command sshhub-ctl manages backends and tokens in the sshhub configuration.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/Trickhish/sshhub/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "add":
		addCmd := flag.NewFlagSet("add", flag.ExitOnError)
		cfgPath := addCmd.String("config", defaultConfigPath(), "path to configuration file")
		hubAddr := addCmd.String("hub", "", "public hub address (host:7000)")
		customToken := addCmd.String("token", "", "custom token (generates secure token if empty)")
		noRestart := addCmd.Bool("no-restart", false, "do not restart sshhub systemd service")
		_ = addCmd.Parse(os.Args[2:])

		args := addCmd.Args()
		if len(args) < 1 {
			log.Fatal("usage: sshhub-ctl add <backend-id> [--config <path>] [--hub <host:port>] [--token <custom-token>]")
		}
		id := args[0]

		token, err := config.AddBackend(*cfgPath, id, *customToken)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		if !*noRestart {
			_ = exec.Command("systemctl", "try-restart", "sshhub").Run()
		}

		hub := *hubAddr
		if hub == "" {
			if cfg, err := config.Load(*cfgPath); err == nil && cfg.Listen.Control != "" {
				control := cfg.Listen.Control
				if strings.HasPrefix(control, ":") {
					hostname, _ := os.Hostname()
					hub = hostname + control
				} else {
					hub = control
				}
			}
		}
		if hub == "" {
			hub = "<hub-host>:7000"
		}

		fmt.Println()
		fmt.Printf("✓ Backend %q successfully registered in %s\n", id, *cfgPath)
		fmt.Println()
		fmt.Println("Generated Token:")
		fmt.Printf("  %s\n", token)
		fmt.Println()
		fmt.Printf("To start the agent on %q, run:\n", id)
		fmt.Printf("  sshhub-agent --hub %s --token %q\n", hub, token)
		fmt.Println()
		fmt.Println("To connect from your client:")
		fmt.Printf("  ssh %s@<hub-domain>\n", id)
		fmt.Printf("  ssh root@%s@<hub-domain>\n", id)
		fmt.Println()

	case "remove", "rm":
		rmCmd := flag.NewFlagSet("remove", flag.ExitOnError)
		cfgPath := rmCmd.String("config", defaultConfigPath(), "path to configuration file")
		noRestart := rmCmd.Bool("no-restart", false, "do not restart sshhub systemd service")
		_ = rmCmd.Parse(os.Args[2:])

		args := rmCmd.Args()
		if len(args) < 1 {
			log.Fatal("usage: sshhub-ctl remove <backend-id> [--config <path>]")
		}
		id := args[0]

		if err := config.RemoveBackend(*cfgPath, id); err != nil {
			log.Fatalf("error: %v", err)
		}
		if !*noRestart {
			_ = exec.Command("systemctl", "try-restart", "sshhub").Run()
		}
		fmt.Printf("✓ Backend %q removed from %s\n", id, *cfgPath)

	case "list", "ls":
		lsCmd := flag.NewFlagSet("list", flag.ExitOnError)
		cfgPath := lsCmd.String("config", defaultConfigPath(), "path to configuration file")
		_ = lsCmd.Parse(os.Args[2:])

		cfg, err := config.Load(*cfgPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}

		fmt.Printf("Backends configured in %s:\n\n", *cfgPath)
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

	default:
		printUsage()
		os.Exit(1)
	}
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
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sshhub-ctl add worker1")
	fmt.Println("  sshhub-ctl add web2 --hub cdn.srv.dury.dev:7000")
	fmt.Println("  sshhub-ctl list")
	fmt.Println("  sshhub-ctl remove worker1")
}
