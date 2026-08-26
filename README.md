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

1. A client connects to the hub's SSH port and authenticates against the hub's
   `authorized_keys` file.
2. The hub inspects the SSH username. A username of the form `alice@web1` is
   split into username `alice` and hostname `web1`; a plain username leaves the
   hostname empty.
3. The hub matches the username/hostname against the routing rules to pick a
   backend.
4. The hub opens an SSH connection to the backend:
   - **Direct mode:** the hub dials the backend's SSH address.
   - **Reverse mode:** the hub opens a multiplexed stream over the agent's
     control connection; the agent bridges that stream to the local `sshd`.
5. The hub authenticates to the backend with the per-backend key or password,
   then bridges the client's channels (shell, exec, port forwards) end to end.

## Routing

Routing rules are evaluated top to bottom; the first match wins. A rule can
match on any combination of:

| Field      | Meaning                                          | Example value      |
| ---------- | ------------------------------------------------ | ------------------ |
| `username` | SSH username (before `@`) from the client        | `alice`            |
| `hostname` | Requested hostname (the part after `@`)          | `web1.example.com` |
| `backend`  | Target backend to forward the connection to      | `web1`             |

Wildcards (`*`) are supported in both `username` and `hostname`. If no rule
matches, the connection is rejected.

To route by hostname, the client includes it in the login name:

```sh
ssh -l alice@web1.example.com sshhub.example.com
```

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

# The hub's own SSH host key.
host_key: "/etc/sshhub/ssh_host_ed25519_key"

# Public keys allowed to connect to the hub.
authorized_keys: "/etc/sshhub/authorized_keys"

# Tokens agents must present when connecting to the control plane.
control_tokens:
  - "change-me-agent-secret"

backends:
  - id: web1
    mode: direct                 # hub dials this server
    address: "10.0.0.10:22"
    username: "deploy"           # user the hub logs in as (defaults to the client's username)
    auth:
      private_key: "/etc/sshhub/backend_keys/web1"
    host_key: "ssh-ed25519 AAAA..."   # pinned backend host key

  - id: db1
    mode: reverse                # server dials the hub
    auth:
      private_key: "/etc/sshhub/backend_keys/db1"
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

- **TLS everywhere:** the control plane listener can be served over TLS
  (`tls_cert`/`tls_key`); agents should verify the hub's certificate.
- **Token hygiene:** rotate control tokens; prefer per-backend tokens over a
  single shared token.
- **Least privilege:** the hub authenticates clients against `authorized_keys`
  and then authenticates to backends with its own per-backend key, so client
  credentials never leave the client.
- **Host key pinning:** pin each backend's SSH host key (`host_key` or
  `host_key_file`) to prevent man-in-the-middle attacks.
- **Exposure:** bind the SSH listener to a network you trust, and rate-limit or
  fail2ban the control listener.

## Comparison to similar projects

| Project      | Routing                       | Reverse support        |
| ------------ | ----------------------------- | ---------------------- |
| `sshpiper`   | username, robust              | limited / via plugins  |
| `sish`       | reverse tunnels (HTTP/TCP)    | yes, tunnel-centric    |
| **sshhub**   | username + hostname (+ both)  | first-class, built-in  |

## Roadmap

- [ ] per-backend authentication tokens.
- [ ] connection metrics and an admin API.
- [ ] regex matching in routing rules.
- [ ] SSH agent forwarding passthrough.
- [ ] TLS between the hub and agents (control plane encryption).

## License

TBD
