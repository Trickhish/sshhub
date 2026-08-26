# sshhub

### Quick 1-Line Install

**1. Install Gateway Server (on your public VPS / Hub):**
```sh
curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-server.sh | sudo bash
```

**2. Install Agent (on your backend node / server behind NAT):**
```sh
curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub <hub-host>:7000 --token "<token>"
```

*(Run `sshhub-ctl add <backend-id>` on your Hub to auto-generate the token and the exact copy-paste agent install command).*

---

SSHub is an SSH gateway and reverse access platform that provides a single entry
point for accessing private servers behind NATs and firewalls.

It supports two operating models:

1. **Direct 1-Command SSH Access (Zero Client Config)**:
   - Connect straight with `ssh server1@hub.example.com` or `ssh root@server1@hub.example.com`.
   - The Hub routes the session to `sshhub-agent` on the backend node.
   - `sshhub-agent` validates the client's public key against local `/root/.ssh/authorized_keys`, allocates a native PTY, and launches the shell.
   - The Hub stores **zero credentials or backdoor keys**.

2. **Layer-4 ProxyJump Passthrough**:
   - `ssh -J hub.example.com root@server1`
   - Bridges raw `direct-tcpip` streams directly to an existing OpenSSH daemon.

```
                          ┌────────────────────────────┐
                          │        sshhub (hub)        │
                          │                            │
   ssh server1@hub ──────▶│  :22   SSH listener        │
   ssh -J hub backend ───▶│  :7000 control listener   │
                          └───────┬────────────┬───────┘
                          direct  │            │ reverse
                          dial    │            │ (agents dial in)
                    ┌─────────────▼──┐      ┌──▼──────────────┐
                    │ backend server │      │ backend server  │
                    │ (reachable)    │      │ (behind NAT)    │
                    └────────────────┘      └─────────────────┘
```

## Features

- **Zero-Config Direct SSH:** Access private backends using `ssh backend@hub` or `ssh user@backend@hub`.
- **CLI Management (`sshhub-ctl`):** Easily add or remove backend nodes with auto-generated secure tokens.
- **1-Line Installers & Auto-Updates:** Quick automated setup and seamless in-band automatic binary updates over the control port.
- **Token-Identified Backends:** Each backend is bound to its unique secret token. Agents do not need to manage or pass their own ID.
- **Node-Level Key Authorization:** The endpoint `sshhub-agent` verifies the user's public key against local `/root/.ssh/authorized_keys`.
- **Embedded PTY Management:** Native pseudo-terminal allocation with dynamic window resize (`SIGWINCH`), interactive shells, and command execution.
- **No Inbound Open Ports Required:** Backend nodes establish outbound reverse yamux tunnels to the hub.
- **No OpenSSH `sshd` Needed:** Endpoints can run purely with `sshhub-agent`.
- **ProxyJump Compatible:** Also works with standard `ssh -J` and `ssh -W`.

## Connecting

### 1. Direct SSH (No Client Config)

```sh
# Login directly to backend "worker1" as root
ssh worker1@hub.example.com

# Specify a custom remote user with user@backend
ssh root@worker1@hub.example.com
ssh alice@web1@hub.example.com

# Run non-interactive commands
ssh worker1@hub.example.com "hostname -f && uptime"
```

### 2. Using ProxyJump (`-J`)

```sh
ssh -J hub.example.com root@worker1
```

### 3. Using `~/.ssh/config`

```sshconfig
Host worker1
  HostName hub.example.com
  User worker1
```

Then simply connect:

```sh
ssh worker1
```

## CLI Management (`sshhub-ctl`)

`sshhub-ctl` lets you manage backends directly from the command line on the central hub.

### Adding a new backend
Generates a secure cryptographic token, registers the backend and its route in `/etc/sshhub/sshhub.yaml`, reloads the service, and outputs the ready-to-run 1-line install command:

```sh
sshhub-ctl add worker1 --hub hub.example.com:7000
```

Output:
```text
✓ Backend "worker1" successfully registered in /etc/sshhub/sshhub.yaml

Generated Token:
  AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k

1-Line Agent Install Command (run on node "worker1"):
  curl -sSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token "AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k"

Manual binary command:
  sshhub-agent --hub hub.example.com:7000 --token "AUPF9eN5kEv-rzo68wNwmICAmqx6cLbyTMD9a5t0m8k"

To connect from your client:
  ssh worker1@hub.example.com
  ssh root@worker1@hub.example.com
```

### Listing backends
```sh
sshhub-ctl list
```

### Removing a backend
```sh
sshhub-ctl remove worker1
```

## Routing Rules & Cheat Sheet

Rules in `routes:` are evaluated **top to bottom** (first match wins):

| Pattern | YAML Rule | Matching SSH Commands |
| :--- | :--- | :--- |
| **Specific `user@server`**<br>*(Only a specific user on a specific node)* | ```yaml\n- username: "alice"\n  hostname: "worker1"\n  backend: worker1\n``` | `ssh alice@worker1@hub` |
| **`*@server` (Any user on `server`)**<br>*(Any user connecting to `@server`)* | ```yaml\n- hostname: "worker1"\n  backend: worker1\n``` | `ssh root@worker1@hub`<br>`ssh alice@worker1@hub` |
| **Direct server name**<br>*(Login user is the server name without `@`)* | ```yaml\n- username: "worker1"\n  backend: worker1\n``` | `ssh worker1@hub` |
| **Wildcard hosts (`web*`, `*.prod`)**<br>*(Glob pattern matching)* | ```yaml\n- hostname: "web*"\n  backend: web-cluster\n``` | `ssh root@web1@hub`<br>`ssh deploy@web-prod@hub` |
| **Catch-All `*`**<br>*(Default fallback if nothing else matched)* | ```yaml\n- username: "*"\n  backend: default-node\n``` | Any connection that didn't match rules above |

### Example Configuration

```yaml
routes:
  # 1. Specific user on specific host
  - username: "backup"
    hostname: "db1"
    backend: db1

  # 2. Any user on a specific host (root@worker1, alice@worker1, etc.)
  - hostname: "worker1"
    backend: worker1

  - hostname: "web1"
    backend: web1

  # 3. Direct server name (ssh worker1@hub or ssh web1@hub)
  - username: "worker1"
    backend: worker1

  - username: "web1"
    backend: web1

  # 4. Fallback if nothing else matched
  - username: "*"
    backend: worker1
```

## Building

Requires Go 1.22+.

```sh
go build -o sshhub ./cmd/sshhub
go build -o sshhub-agent ./cmd/sshhub-agent
go build -o sshhub-ctl ./cmd/sshhub-ctl
```

## Configuration

The hub is configured with `/etc/sshhub/sshhub.yaml`:

```yaml
listen:
  ssh: ":22"        # where SSH clients connect
  control: ":7000"  # where agents connect (reverse mode)

host_key: "/etc/sshhub/ssh_host_ed25519_key"

backends:
  - id: worker1
    mode: reverse
    token: "TNgPdS6pc0V7I0iSyP0Rclvy82txSuy7qm0FdtNKIcY="

  - id: web1
    mode: direct
    address: "10.0.0.10:22"

routes:
  - hostname: "worker1"
    backend: worker1

  - hostname: "web1"
    backend: web1

  - username: "*"
    backend: worker1
```

## License

MIT
