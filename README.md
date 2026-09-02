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

Hub Key Pin:
  sha256:kTv3xQ2mB8pL5wR9cN4aY7jZ1fH6eU0oI2gX8vMdP4s=

1-Line Agent Install Command (run on node "worker1"):
  curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token "AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k" --hub-pin "sha256:kTv3xQ2mB8pL5wR9cN4aY7jZ1fH6eU0oI2gX8vMdP4s="
```

The **hub key pin** lets the agent verify it is talking to your Hub before it
sends its token. It is required; retrieve it any time with `sshhub-ctl pin`.

### 3. Install the Agent (on your private node behind NAT)
Paste the generated command on your worker machine:
```sh
curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token "<token>" --hub-pin "<pin>"
```

### 4. Connect!
```sh
ssh worker1@hub.example.com
```

---

## ✨ Key Features

- ⚡ **Instant Pre-Built Installs:** Install scripts fetch official GitHub Releases in <1s (no Go compiler required).
- 🔄 **Fully Automated Updates:** Hub and agents automatically self-update over verified HTTPS whenever you push a new GitHub release tag.
- 🛡️ **No Backend Credentials on the Hub:** The Hub holds no key or password that grants shell access to a node; every login is validated against the node's own `authorized_keys` by the agent.
- 🔒 **Pinned, Encrypted Control Plane:** Agents reach the Hub over TLS and authenticate it by public key pin, so registration tokens cannot be intercepted.
- 👤 **Least-Privilege Sessions:** Sessions drop to the Unix account named by the route's `end_user` (default `root`), which is set in config and never derived from client input.
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
| `sshhub-ctl add <id> --end-user <user>` | As above, with sessions running as a specific Unix account |
| `sshhub-ctl remove <id>` | Remove a backend node and its routing entries from the configuration |
| `sshhub-ctl list` | List all configured backends, their end users, and tokens |
| `sshhub-ctl pin` | Show the Hub key pin agents need for `--hub-pin` |
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

**Which Unix account does the session run as?** Not the one in the SSH command.
`username:`/`hostname:` are *routing identifiers* and need not be real accounts.
The account is the matched route's `end_user:` (default `root`), so `ssh
alice@worker1@hub` runs as whatever that route specifies — a client cannot pick
a privileged account by choosing its login name. The client's key must still be
in that account's `authorized_keys` on the node.

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
   │  • Hub cannot decrypt sessions    │     │  • Immune to Hub Compromise       │
   └───────────────────────────────────┘     └───────────────────────────────────┘
   ┌───────────────────────────────────┐     ┌───────────────────────────────────┐
   │        Control Plane              │     │        Direct SSH Mode            │
   │  • TLS with hub key pinning       │     │  • No backend creds on the Hub    │
   │  • Agent host keys pinned         │     │  • Agent authorizes via own keys  │
   │  • Tokens never sent in clear     │     │  • Hub DOES terminate the session │
   └───────────────────────────────────┘     └───────────────────────────────────┘
```

1. **ProxyJump Mode (End-to-End Encryption)**:
   - When using `ssh -J hub.example.com node`, key exchange and public key authentication occur **strictly between your client and the node**.
   - In this mode the Hub is a byte pipe and cannot read the session.

2. **Direct Mode (`ssh worker1@hub`) — what the Hub can and cannot do**:
   - The Hub holds **no credential** that grants shell access to any node. Authorization is delegated to the agent, which checks the client's key against the target account's own `authorized_keys`.
   - Sessions run as the route's `end_user` (default `root`), set in config and never derived from the client's login string.
   - **However:** in this mode the Hub terminates the client's SSH connection, so a Hub compromised *while running* can observe traffic and open sessions to nodes that clients are authorized for. This is inherent to any username-routed jump host. Use ProxyJump mode where that matters.

3. **Control Plane**:
   - Agents connect over TLS and authenticate the Hub by **public key pin** (`--hub-pin`), so registration tokens cannot be captured on-path.
   - The Hub pins each agent's SSH host key, and refuses to connect to a backend whose key it does not know.

4. **Supply Chain Protection on Auto-Updates**:
   - `sshhub-agent` updates exclusively from **GitHub Releases over verified TLS/HTTPS**.
   - The Hub never distributes raw binaries or private keys. A compromised Hub cannot inject arbitrary malicious code onto connected nodes.

5. **Abuse Resistance**:
   - Per-source-IP connection rate limiting, a concurrent-handshake cap, and temporary blocking after repeated authentication failures.
   - The Hub does not accept password authentication in any form.

---

## ⚙️ Configuration Reference

The Gateway configuration is located at `/etc/sshhub/sshhub.yaml`:

```yaml
listen:
  ssh: ":22"                 # Port where SSH clients connect
  control: ":7000"           # Port where reverse agents connect

public_host: "hub.example.com" # Public domain used in sshhub-ctl output

host_key: "/etc/sshhub/ssh_host_ed25519_key"

# How long a release must be public before the hub installs it automatically.
#   48h      wait two days (default when omitted) -- a soak period, so a bad
#            release has time to be noticed and replaced before it propagates
#   0        install as soon as a release appears
#   false    disable automatic updates entirely (update with 'sshhub-ctl update')
# The newest release at the end of the wait is what installs, so an emergency
# fix supersedes the release it fixes rather than queueing behind it.
# auto_update_wait: 48h

# TLS for the control plane. If omitted, a self-signed certificate is
# generated at /etc/sshhub/control-cert.pem on first start and agents pin it.
# tls_cert: "/etc/sshhub/control-cert.pem"
# tls_key:  "/etc/sshhub/control-key.pem"

backends:
  - id: worker1
    mode: reverse           # "reverse" is the only supported mode
    token: "TNgPdS6pc0V7I0iSyP0Rclvy82txSuy7qm0FdtNKIcY="

  - id: db1
    mode: reverse
    token: "9dK2mVx7QpL4tR8sN1wZbC3fH6jY0aE5uI2oP7gX4vM="

routes:
  # end_user is the Unix account the session runs as on the node.
  # It comes only from this config -- never from the client's login string --
  # and defaults to root when omitted.
  - hostname: "worker1"
    backend: worker1
    end_user: deploy        # ssh worker1@hub -> runs as deploy

  - username: "admin"
    hostname: "worker1"
    backend: worker1        # ssh admin@worker1@hub -> runs as root (default)

  - hostname: "db1"
    backend: db1

  - username: "*"
    backend: worker1
```

> **Note:** `mode: direct` was removed. The hub only routes to nodes running
> `sshhub-agent`, which authenticates the client against the node's own
> `authorized_keys`. A config still containing `direct`, or a `username:` field
> on a backend, is rejected at startup with a migration message.

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
