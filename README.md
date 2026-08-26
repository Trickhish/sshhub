# sshhub

SSHub is an SSH gateway that acts as a single entry point and transparently
routes each incoming SSH connection to a backend server. Routing is decided by
the **username**, the **requested hostname**, or a combination of both.

SSHub allows **direct SSH connections with zero client configuration**:
- `ssh -p 2222 cidev@sshhub.example.com`
- `ssh -p 2222 root@cidev@sshhub.example.com`
- `ssh -p 2222 alice@web1@sshhub.example.com`

It also supports standard **ProxyJump (`-J`)** and **`ProxyCommand`** (`direct-tcpip`) passthrough.

SSHub supports two transport models so it fits both classic and NAT/firewall
restricted topologies:

- **Direct mode** — the central server dials backend SSH servers directly.
- **Reverse mode** — backend servers establish an outbound control connection
  to the central server, so backends behind NATs or strict firewalls can still
  be reached without opening inbound ports.

```
                          ┌────────────────────────────┐
                          │        sshhub (hub)        │
                          │                            │
   ssh -p 2222 cidev@hub ─▶│  :2222 SSH listener       │
   ssh -J hub backend   ──▶│  :7000 control listener   │
                          └───────┬────────────┬───────┘
                          direct  │            │ reverse
                          dial    │            │ (agents dial in)
                    ┌─────────────▼──┐      ┌──▼──────────────┐
                    │ backend server │      │ backend server  │
                    │ (reachable)    │      │ (behind NAT)    │
                    └────────────────┘      └─────────────────┘
```

## Features

- **Direct login (Zero Client Config):** Connect straight into any backend with standard `ssh user@backend@hub` or `ssh backend@hub`. Full interactive PTY, shell, commands, window resizing, SFTP, and signals.
- **ProxyJump / Passthrough:** Works seamlessly with `ssh -J` and `ssh -W` (`direct-tcpip`) for raw byte bridging.
- **Dynamic Routing:** Route SSH connections by username, hostname, or glob patterns.
- **Direct & Reverse Transports:** Direct TCP connections for public servers and yamux multiplexed reverse tunnels for hosts behind NAT.
- **Central Host Key Authorization:** Authorize the Hub's public key once in `/root/.ssh/authorized_keys` across backends.
- **Single Static Binaries:** Zero dependencies for `sshhub` gateway and `sshhub-agent`.

## Connecting

### 1. Direct SSH Connection (No Client Config Required)

Connect straight through the gateway specifying either the backend or `user@backend`:

```sh
# Login directly as the backend's configured user (or root)
ssh -p 2222 cidev@cdn.srv.dury.dev

# Specify a custom remote user with user@backend
ssh -p 2222 root@cidev@cdn.srv.dury.dev
ssh -p 2222 alice@web1@cdn.srv.dury.dev

# Run non-interactive commands
ssh -p 2222 cidev@cdn.srv.dury.dev "hostname -f && uptime"
```

### 2. Using ProxyJump (`-J`)

```sh
ssh -J cdn.srv.dury.dev:2222 root@cidev
```

### 3. Using `~/.ssh/config`

```sshconfig
Host cdn.hub
  HostName cdn.srv.dury.dev
  Port 2222

Host cidev
  HostName cdn.srv.dury.dev
  Port 2222
  User cidev
```

Then simply run:

```sh
ssh cidev
```

## Routing

Routing rules are evaluated top to bottom; the first match wins. A rule can
match on any combination of:

| Field      | Meaning                                          | Example value      |
| ---------- | ------------------------------------------------ | ------------------ |
| `username` | SSH username (before `@`) from the client        | `alice`            |
| `hostname` | Requested hostname (or target host after `@`)   | `web1.example.com` |
| `backend`  | Target backend to forward the connection to      | `web1`             |

Wildcards (`*`) are supported in both `username` and `hostname`. If no rule
matches, the connection is rejected.

## Building

Requires Go 1.22+.

```sh
go build -o sshhub ./cmd/sshhub
go build -o sshhub-agent ./cmd/sshhub-agent
```

## Configuration

The hub is configured with a single YAML file (`/etc/sshhub/sshhub.yaml`):

```yaml
listen:
  ssh: ":2222"      # where SSH clients connect
  control: ":7000"  # where agents connect (reverse mode)

# The hub's SSH host key.
host_key: "/etc/sshhub/ssh_host_ed25519_key"

# (Optional) Public keys allowed to connect through the hub.
# If omitted, any authenticated client can connect.
authorized_keys: "/etc/sshhub/authorized_keys"

# Tokens agents must present when connecting to the control plane.
control_tokens:
  - "change-me-agent-secret"

backends:
  - id: web1
    mode: direct                 # hub dials this server directly
    address: "10.0.0.10:22"

  - id: cidev
    mode: reverse                # server dials the hub via sshhub-agent
    username: "root"

routes:
  - match:
      username: "deploy"
      hostname: "web1.example.com"
    backend: web1

  - match:
      username: "cidev"
    backend: cidev

  # default fallback
  - match:
      username: "*"
    backend: cidev
```

### Running the hub

```sh
sshhub --config /etc/sshhub/sshhub.yaml
```

### Running an agent (reverse mode)

```sh
sshhub-agent \
  --hub cdn.srv.dury.dev:7000 \
  --token change-me-agent-secret \
  --backend cidev \
  --sshd 127.0.0.1:22
```

The agent connects out to the hub, authenticates with its token, and registers
`cidev` as available. Incoming client sessions for `cidev` are then multiplexed over
this single outbound connection.

## License

MIT
