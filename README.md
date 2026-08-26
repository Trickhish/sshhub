# sshhub

SSHub is an SSH gateway that acts as a single entry point and transparently
routes each incoming SSH connection to a backend server. Routing is decided by
the **username**, the **requested hostname**, or a combination of both.

SSHub supports two transport models so it fits both classic and NAT/firewall
restricted topologies:

- **Direct mode** — the central server dials backend SSH servers directly.
- **Reverse mode** — backend servers establish an outbound control connection
  to the central server, so backends behind NATs or strict firewalls can still
  be reached without opening inbound ports.

```
                          ┌────────────────────────────┐
                          │        sshhub (hub)         │
                          │                            │
   ssh user@hostname ───▶ │  :22   SSH listener        │
                          │  :7000 control listener     │
                          └───────┬────────────┬───────┘
                          direct  │            │ reverse
                          dial    │            │ (agents dial in)
                    ┌─────────────▼──┐      ┌──▼──────────────┐
                    │ backend server │      │ backend server  │
                    │ (reachable)    │      │ (behind NAT)    │
                    └────────────────┘      └─────────────────┘
```

## Features

- Route SSH connections by username, hostname, or both.
- Direct and reverse transport modes, usable side by side.
- Per-backend configuration (address, host key, allowed usernames).
- Agents authenticate to the control plane with a shared token.
- Multiple SSH sessions multiplexed over a single reverse connection.
- Single static binary for the hub, and a single static binary for the agent.

## How it works

1. A client runs `ssh alice@web1.example.com` and points at the hub's SSH port
   (directly, or via DNS/`~/.ssh/config`).
2. The hub inspects the SSH `User` field (the username) and, if SNI-style
   hostname routing is enabled, the requested hostname.
3. The hub picks a matching backend and forwards the raw SSH protocol:
   - **Direct mode:** the hub opens a new TCP connection to the backend's
     SSH port and bridges the two sockets.
   - **Reverse mode:** the hub opens a new multiplexed stream over the
     already-established control connection; the agent bridges that stream to
     the local `sshd`.
4. The client and the backend complete their normal SSH handshake end to end.
   The hub never needs the client's private keys or the backend's credentials.

## Routing

Routing rules are evaluated top to bottom; the first match wins. A rule can
match on any combination of:

| Field      | Meaning                                    | Example value            |
| ---------- | ------------------------------------------ | ------------------------ |
| `username` | SSH `User` field from the client           | `alice`                  |
| `hostname` | Requested hostname (requires SNI support)  | `web1.example.com`       |
| `backend`  | Target backend to forward the connection to | `web1`                   |

Wildcards (`*`) are supported in both `username` and `hostname`. If no rule
matches, the connection is rejected.

## Building

Requires Go 1.22+.

```sh
go build -o sshhub ./cmd/sshhub
go build -o sshhub-agent ./cmd/sshhub-agent
```

## Configuration

The hub is configured with a single YAML file.

```yaml
listen:
  ssh: ":22"       # where SSH clients connect
  control: ":7000" # where agents connect (reverse mode)

# Tokens agents must present when connecting to the control plane.
control_tokens:
  - "change-me-agent-secret"

backends:
  - id: web1
    mode: direct                 # hub dials this server
    address: "10.0.0.10:22"
    host_key: "ssh-ed25519 AAAA..."

  - id: db1
    mode: reverse                # server dials the hub
    # no address needed; the agent registers its availability

routes:
  - match:
      username: "deploy"
      hostname: "web1.example.com"
    backend: web1

  - match:
      username: "backup"
    backend: db1

  # default fallback
  - match:
      username: "*"
    backend: web1
```

### Running the hub

```sh
./sshhub --config sshhub.yaml
```

### Running an agent (reverse mode)

```sh
./sshhub-agent \
  --hub sshhub.example.com:7000 \
  --token change-me-agent-secret \
  --backend db1 \
  --sshd 127.0.0.1:22
```

The agent connects out to the hub, authenticates with its token, and registers
`db1` as available. Incoming client sessions for `db1` are then multiplexed over
this connection.

## Security considerations

- **TLS everywhere:** the control plane listener should be served over TLS;
  agents must verify the hub's certificate and vice versa.
- **Token hygiene:** rotate control tokens; prefer per-backend tokens over a
  single shared token.
- **Least privilege:** the hub never terminates SSH authentication itself, so
  user keys and passwords pass straight through to the backend.
- **Host key pinning:** for direct mode, pin the backend's SSH host key in the
  configuration to prevent man-in-the-middle attacks.
- **Exposure:** bind the SSH listener to a network you trust, and rate-limit or
  fail2ban the control listener.

## Comparison to similar projects

| Project      | Routing                       | Reverse support        |
| ------------ | ----------------------------- | ---------------------- |
| `sshpiper`   | username, robust              | limited / via plugins  |
| `sish`       | reverse tunnels (HTTP/TCP)    | yes, tunnel-centric    |
| **sshhub**   | username + hostname (+ both)  | first-class, built-in  |

## Roadmap

- [ ] SNI-based hostname routing on the SSH listener.
- [ ] per-backend authentication tokens.
- [ ] connection metrics and an admin API.
- [ ] wildcard and regex matching in routing rules.
- [ ] SSH agent forwarding passthrough.

## License

TBD
