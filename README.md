# sshhub

SSHub is an SSH gateway and reverse access platform that provides a single entry
point for accessing private servers behind NATs and firewalls.

It supports two operating models:

1. **Direct 1-Command SSH Access (Zero Client Config)**:
   - Connect straight with `ssh -p 2222 cidev@cdn.srv.dury.dev` or `ssh -p 2222 root@cidev@cdn.srv.dury.dev`.
   - The Hub routes the session to `sshhub-agent` on the backend node.
   - `sshhub-agent` validates the client's public key against local `/root/.ssh/authorized_keys`, allocates a native PTY, and launches the shell.
   - The Hub stores **zero credentials or backdoor keys**.

2. **Layer-4 ProxyJump Passthrough**:
   - `ssh -J cdn.srv.dury.dev:2222 root@cidev`
   - Bridges raw `direct-tcpip` streams directly to an existing OpenSSH daemon.

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

- **Zero-Config Direct SSH:** Access private backends using `ssh -p 2222 backend@hub` or `ssh -p 2222 user@backend@hub`.
- **Node-Level Key Authorization:** The endpoint `sshhub-agent` verifies the user's public key against local `/root/.ssh/authorized_keys`.
- **Embedded PTY Management:** Native pseudo-terminal allocation with dynamic window resize (`SIGWINCH`), interactive shells, and command execution.
- **No Inbound Open Ports Required:** Backend nodes establish outbound reverse yamux tunnels to the hub.
- **No OpenSSH `sshd` Needed:** Endpoints can run purely with `sshhub-agent`.
- **ProxyJump Compatible:** Also works with standard `ssh -J` and `ssh -W`.

## Connecting

### 1. Direct SSH (No Client Config)

```sh
# Login directly to backend "cidev" as root
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
Host cidev
  HostName cdn.srv.dury.dev
  Port 2222
  User cidev
```

Then simply connect:

```sh
ssh cidev
```

## Building

Requires Go 1.22+.

```sh
go build -o sshhub ./cmd/sshhub
go build -o sshhub-agent ./cmd/sshhub-agent
```

## Configuration

The hub is configured with `/etc/sshhub/sshhub.yaml`:

```yaml
listen:
  ssh: ":2222"      # where SSH clients connect
  control: ":7000"  # where agents connect (reverse mode)

host_key: "/etc/sshhub/ssh_host_ed25519_key"

control_tokens:
  - "sshhub-token-secret-2026"

backends:
  - id: cidev
    mode: reverse

routes:
  - match:
      hostname: "cidev"
    backend: cidev
  - match:
      username: "*"
    backend: cidev
```

### Running an agent (reverse mode)

```sh
# Native PTY execution mode (default, no sshd needed)
sshhub-agent \
  --hub cdn.srv.dury.dev:7000 \
  --token sshhub-token-secret-2026 \
  --backend cidev

# Or optional bridge mode to an existing local sshd daemon
sshhub-agent \
  --hub cdn.srv.dury.dev:7000 \
  --token sshhub-token-secret-2026 \
  --backend cidev \
  --sshd 127.0.0.1:22
```

## License

MIT
