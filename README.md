<div align="center">

# 🌐 SSHub

**A modern, zero-trust SSH gateway and reverse proxy platform.**  
*Seamlessly connect to servers behind NATs, firewalls, and private networks with zero client configuration.*

[![GitHub Release](https://img.shields.io/github/v/release/Trickhish/sshhub?color=blue&logo=github)](https://github.com/Trickhish/sshhub/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Trickhish/sshhub?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%5Bamd64%20%7C%20arm64%5D-lightgrey?logo=linux)](https://github.com/Trickhish/sshhub/releases)
[![Security](https://img.shields.io/badge/security-zero--trust%20%7C%20e2e-green?logo=ssh)](https://github.com/Trickhish/sshhub#security--zero-trust-model)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Key Features](#-key-features)
- [Connecting to Nodes](#-connecting-to-nodes)
- [CLI Management (`sshhub-ctl`)](#-cli-management-sshhub-ctl)
- [Routing Rules & Cheatsheet](#-routing-rules--cheatsheet)
- [Security & Zero-Trust Model](#-security--zero-trust-model)
- [Configuration Reference](#-configuration-reference)
- [Manual Compilation](#-manual-compilation)
- [License](#-license)

---

## 💡 Overview

**SSHub** bridges private infrastructure and developers without requiring VPNs, complex port-forwarding, or backdoor credentials. 

Nodes running `sshhub-agent` establish an **outbound reverse Yamux tunnel** to a central SSHub Gateway. You can access any node directly with standard OpenSSH commands (`ssh worker1@hub.example.com` or `ssh -J hub.example.com worker1`).

### Two Flexible Modes:
1. **Zero-Config Direct SSH (`ssh worker1@hub.example.com`)**:
   - No `~/.ssh/config` modifications needed on client laptops.
   - The Hub routes sessions to the node's native `sshhub-agent`.
   - The agent authenticates the user directly against `/root/.ssh/authorized_keys`, spawns a native PTY, and launches the shell.
2. **Layer-4 ProxyJump Passthrough (`ssh -J hub.example.com root@worker1`)**:
   - Bridges raw TCP byte streams directly to an existing OpenSSH daemon (`sshd`).
   - 100% end-to-end cryptographic encryption between your laptop and the backend.

---

## 🏗️ Architecture

```
                          ┌────────────────────────────┐
                          │        SSHub Gateway       │
                          │      (Public VPS / Hub)    │
   ssh worker1@hub ──────▶│                            │
   ssh -J hub worker1 ───▶│  :22   SSH listener        │
                          │  :7000 control listener    │
                          └───────┬────────────┬───────┘
                          direct  │            │ reverse
                          dial    │            │ (agents dial outbound)
                    ┌─────────────▼──┐      ┌──▼──────────────┐
                    │ backend server │      │ backend server  │
                    │  (reachable)   │      │  (behind NAT)   │
                    └────────────────┘      └─────────────────┘
```

---

## 🚀 Quick Start

### 1. Install the Gateway (on your public VPS / Hub)
```sh
curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-server.sh | sudo bash
```

### 2. Register a Node on the Hub
Run `sshhub-ctl add` to generate a secure registration token and copy-paste installer:
```sh
sshhub-ctl add worker1
```

```text
✓ Backend "worker1" successfully registered in /etc/sshhub/sshhub.yaml

Generated Token:
  AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k

1-Line Agent Install Command (run on node "worker1"):
  curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token "AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k"
```

### 3. Install the Agent (on your private node behind NAT)
Paste the generated command on your worker machine:
```sh
curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token "<token>"
```

### 4. Connect!
```sh
ssh worker1@hub.example.com
```

---

## ✨ Key Features

- ⚡ **Instant Pre-Built Installs:** Install scripts fetch official GitHub Releases in <1s (no Go compiler required).
- 🔄 **Fully Automated Updates:** Hub and agents automatically self-update over verified HTTPS whenever you push a new GitHub release tag.
- 🛡️ **Zero-Trust Security:** Zero credentials or private keys stored on the Hub; node authentication validated directly against local `authorized_keys`.
- 🖥️ **Embedded Native PTY:** Full terminal support including interactive shells, cursor positioning, and dynamic window resizing (`SIGWINCH`).
- 🚪 **Zero Inbound Open Ports:** Nodes connect outbound to the Hub—ideal for home labs, private VPCs, and CGNAT environments.
- 📦 **No OpenSSH Daemon Required:** Endpoints can run purely with the standalone `sshhub-agent` binary.
- 🔀 **ProxyJump & ProxyCommand Compatible:** Works seamlessly with `ssh -J`, `ssh -W`, and existing Ansible/Terraform workflows.

---

## 💻 Connecting to Nodes

### 1. Direct SSH (Zero Client Configuration)

```sh
# Login directly as root:
ssh worker1@hub.example.com

# Target a specific remote user:
ssh root@worker1@hub.example.com
ssh dev@web1@hub.example.com

# Run non-interactive remote commands:
ssh worker1@hub.example.com "uptime && uname -a"
```

### 2. ProxyJump (`-J`)

```sh
ssh -J hub.example.com root@worker1
```

### 3. Using `~/.ssh/config` (Short Aliases)

Add to your local `~/.ssh/config`:

```sshconfig
Host worker1
  HostName hub.example.com
  User worker1
```

Then simply connect with:

```sh
ssh worker1
```

---

## 🛠️ CLI Management (`sshhub-ctl`)

`sshhub-ctl` provides a command-line interface for managing backend routes and updates on the Hub.

| Command | Description |
| :--- | :--- |
| `sshhub-ctl add <id>` | Generate a secure token, create route rules, and display the agent 1-liner |
| `sshhub-ctl remove <id>` | Remove a backend node and its routing entries from the configuration |
| `sshhub-ctl list` | List all configured backends, connection modes, and tokens |
| `sshhub-ctl update` | Check GitHub Releases and download/apply the latest Gateway update |
| `sshhub-ctl update --check` | Check if a newer version is available without applying it |
| `sshhub-ctl version` | Display current installed version |

---

## 🧭 Routing Rules & Cheatsheet

SSHub evaluates rules in `routes:` from **top to bottom** (first match wins):

| Pattern | YAML Rule | Matching SSH Commands |
| :--- | :--- | :--- |
| **Exact User & Server** | `username: "alice"`<br>`hostname: "worker1"` | `ssh alice@worker1@hub` |
| **Any User on Server** | `hostname: "worker1"` | `ssh root@worker1@hub`<br>`ssh alice@worker1@hub` |
| **Direct Server Alias** | `username: "worker1"` | `ssh worker1@hub` |
| **Wildcard Host Glob** | `hostname: "web*"` | `ssh root@web1@hub`<br>`ssh root@web-prod@hub` |
| **Catch-All Default** | `username: "*"` | Any connection not matched above |

```yaml
routes:
  # Route 1: Target specific user on specific host
  - username: "backup"
    hostname: "db1"
    backend: db1

  # Route 2: Single-word alias routing (ssh worker1@hub -> root on worker1)
  - hostname: "worker1"
    backend: worker1

  # Route 3: Fallback default node
  - username: "*"
    backend: worker1
```

---

## 🛡️ Security & Zero-Trust Model

SSHub is built with defense-in-depth:

```
                  ┌─────────────────────────────────────────┐
                  │           Threat Model Defense          │
                  └─────────────────────────────────────────┘
   ┌───────────────────────────────────┐     ┌───────────────────────────────────┐
   │         ProxyJump Mode            │     │       HTTPS GitHub Updates        │
   │  • End-to-End Cryptography        │     │  • Zero Signing Keys on Hub       │
   │  • Hub is a blind Layer 4 pipe    │     │  • Agents download from GitHub    │
   │  • Impossible for Hub to decrypt  │     │  • Immune to Hub Compromise       │
   └───────────────────────────────────┘     └───────────────────────────────────┘
```

1. **ProxyJump Mode (100% E2E Encryption)**:
   - When using `ssh -J hub.example.com node`, Diffie-Hellman Key Exchange and public key authentication occur **strictly between your client and the node**.
   - Even if an attacker gains full root access on the Hub VPS, they cannot decrypt sessions or compromise backend nodes.

2. **Supply Chain Protection on Auto-Updates**:
   - `sshhub-agent` updates exclusively from **GitHub Releases over verified TLS/HTTPS**.
   - The Hub never distributes raw binaries or private keys. A compromised Hub cannot inject arbitrary malicious code onto connected nodes.

---

## ⚙️ Configuration Reference

The Gateway configuration is located at `/etc/sshhub/sshhub.yaml`:

```yaml
listen:
  ssh: ":22"                 # Port where SSH clients connect
  control: ":7000"           # Port where reverse agents connect

public_host: "hub.example.com" # Public domain used in sshhub-ctl output

host_key: "/etc/sshhub/ssh_host_ed25519_key"

backends:
  - id: worker1
    mode: reverse
    token: "TNgPdS6pc0V7I0iSyP0Rclvy82txSuy7qm0FdtNKIcY="

  - id: db1
    mode: direct
    address: "10.0.0.10:22"

routes:
  - hostname: "worker1"
    backend: worker1

  - hostname: "db1"
    backend: db1

  - username: "*"
    backend: worker1
```

---

## 🔧 Manual Compilation & Installer Options

### 1-Line Installer Options

| Option | Description |
| :--- | :--- |
| `--rebuild` (or `--build`) | Force compilation from Git source using Go instead of downloading pre-built releases |
| `--version <vX.Y.Z>` | Install a specific release version (defaults to latest stable) |
| `--hub <host:port>` | Hub control address (agent installer) |
| `--token <token>` | Agent registration token (agent installer) |
| `--ssh-port <port>` | Gateway SSH listener port (default: `:22`) |
| `--control-port <port>` | Gateway Control plane port (default: `:7000`) |

### Manual Build from Source

Requires Go 1.22+:

```sh
# Clone repository:
git clone https://github.com/Trickhish/sshhub.git
cd sshhub

# Build all binaries:
go build -ldflags="-s -w" -o sshhub ./cmd/sshhub
go build -ldflags="-s -w" -o sshhub-agent ./cmd/sshhub-agent
go build -ldflags="-s -w" -o sshhub-ctl ./cmd/sshhub-ctl
```

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.
