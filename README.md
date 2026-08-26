# sshhub

SSHub is an SSH gateway that acts as a single entry point and transparently
routes incoming SSH connections to backend servers using **pure Layer-4 passthrough**.

SSHub relays the raw, end-to-end encrypted SSH stream between the client and the
backend `sshd`. Client credentials, public keys, and host keys are negotiated
directly between the client and the backend server without the hub terminating
or impersonating authentication.

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
   ssh -J hub backend ───▶│  :2222 SSH listener       │
                          │  :7000 control listener   │
                          └───────┬────────────┬───────┘
                          direct  │            │ reverse
                          dial    │            │ (agents dial in)
                    ┌─────────────▼──┐      ┌──▼──────────────┐
                    │ backend server │      │ backend server  │
                    │ (reachable)    │      │ (behind NAT)    │
                    └────────────────┘      └─────────────────┘
```

## Features

- **End-to-End Cryptographic Passthrough:** Client authenticates directly against the backend `sshd` with the client's own key or password. The hub never stores or impersonates backend credentials.
- **Zero-Knowledge Gateway:** The hub only sees encrypted traffic and bridges `direct-tcpip` channels.
- **Dynamic Routing:** Route SSH connections by hostname, username, or glob patterns.
- **Direct & Reverse Transports:** Direct TCP connections for public servers and yamux multiplexed reverse tunnels for hosts behind NAT.
- **Single Static Binaries:** Zero dependencies for `sshhub` gateway and `sshhub-agent`.

## Connecting

### 1. Using ProxyJump (`-J`)

```sh
ssh -J cdn.srv.dury.dev:2222 root@cidev
```

### 2. Using `~/.ssh/config` (Simple 1-Command Access)

Add this block to your local machine's `~/.ssh/config`:

```sshconfig
Host *.hub cidev web1
  ProxyJump cdn.srv.dury.dev:2222
```

Once configured, you can connect directly with no extra flags:

```sh
ssh root@cidev
```

### 3. Using ProxyCommand (`-W`)

```sh
ssh -o ProxyCommand="ssh -p 2222 -W %h:%p cdn.srv.dury.dev" root@cidev
```

## Routing

Routing rules are evaluated top to bottom; the first match wins. A rule can
match on any combination of:

| Field      | Meaning                                          | Example value      |
| ---------- | ------------------------------------------------ | ------------------ |
| `username` | SSH username from the client                     | `alice`            |
| `hostname` | Target hostname after `@` (e.g. `root@cidev`)    | `cidev`            |
| `backend`  | Target backend to forward the connection to      | `cidev`            |

Wildcards (`*`) are supported in both `username` and `hostname`.

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

# (Optional) Public keys allowed to connect to the hub.
# If omitted, any client can open passthrough tunnels to configured backends.
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

routes:
  - match:
      hostname: "web1"
    backend: web1

  - match:
      hostname: "cidev"
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

## License

MIT
