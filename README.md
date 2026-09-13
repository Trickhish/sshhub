# SSHub

SSHub is a forwarding-only SSH gateway for machines behind NAT. Agents dial
outbound TLS/Yamux tunnels to the hub and forward streams to a fixed loopback
OpenSSH server. There is no embedded shell, SFTP server, or hub-asserted backend
identity. Direct `ssh node@hub` sessions are refused.

## Connecting

```sh
ssh -J alice@hub.example.com deploy@worker1
scp -o ProxyJump=alice@hub.example.com file worker1:/tmp/
sftp -o ProxyJump=alice@hub.example.com deploy@worker1
```

Or configure:

```sshconfig
Host hub
    HostName hub.example.com
    User alice
    IdentityFile ~/.ssh/jump_key
    IdentitiesOnly yes
    ForwardAgent no
    StrictHostKeyChecking yes

Host worker1
    HostName worker1
    User deploy
    ProxyJump hub
    IdentityFile ~/.ssh/backend_key
    IdentitiesOnly yes
    ForwardAgent no
    StrictHostKeyChecking yes
```

Install the hub and backend public host keys into the client's known_hosts
through an independent trusted channel before connecting. Never obtain the
backend trust anchor solely from the hub you want to exclude from trust.

The outer jump key grants transport access only. OpenSSH independently verifies
the inner client's private-key possession and applies its own account, key,
forced-command, PTY and SFTP policies. Do not authorize the hub's host key or any
hub-held key on backends. Do not enable agent forwarding or host-based trust.

## Hub configuration

`/etc/sshhub/sshhub.yaml`, owned by root with mode 0600:

```yaml
listen:
  ssh: ':22'
  control: ':7000'
host_key: /etc/sshhub/ssh_host_ed25519_key
auto_update_wait: false
backends:
  - id: worker1
    mode: reverse
    token: '<random 32-byte token>'
jump_users:
  - name: alice
    keys:
      - 'ssh-ed25519 AAAA... alice-jump'
    backends: [worker1]
```

Only exact backend IDs on logical destination port 22 are forwarded. The actual
loopback address is configured locally on the agent, never chosen by the hub.
An empty jump_users list grants nobody access. Keys with authorized_keys options
are rejected rather than silently stripping their restrictions.

## Installation and migration from 0.6.x

This is a breaking migration. Keep independent administrative access while
upgrading both hub and agents. Old embedded-agent installations are incompatible.

1. Install/configure OpenSSH on every backend. It must listen at the agent's
   fixed loopback endpoint (default 127.0.0.1:22). Configure public-key-only auth,
   account restrictions and forwarding policy there. Backend OpenSSH sees the
   agent's loopback address, not the original client's IP; source-IP policies
   must account for this.
2. Independently provision host keys on clients. Keep backend private keys off
   the hub. Remove any legacy hub host key from account authorized_keys after
   verifying its identity and preserving your own access.
3. Add jump_users with explicit keys and backend grants. Legacy routes/end_user
   fields no longer define sessions; migrate and remove them.
4. Download the release tarball for the host architecture and
   sshhub-manifest.json into one directory. Use installer scripts from a trusted
   checkout, not a script fetched dynamically from the hub.
5. Put the registration token in a root-only file and run:

```sh
sudo scripts/install-agent.sh --release-dir /path/to/release \
  --hub hub.example.com:7000 --hub-pin 'sha256:...' \
  --token-file /root/worker1.token --sshd 127.0.0.1:22
sudo scripts/install-server.sh --release-dir /path/to/release
```

The scripts also support one-command installation, while still verifying the
signed manifest and artifact digest before installation:

```sh
curl -fsSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-server.sh | sudo bash
curl -fsSL https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --hub-pin 'sha256:...' --token 'REGISTRATION_TOKEN'
```

Installers require Python 3, OpenSSL with Ed25519 support, and systemd. On
systemd 250 or newer the token is passed via LoadCredential; on older systemd it
is stored root-owned and group-readable by the agent account instead. In both
cases the token never appears in the service command line. They verify a pinned Ed25519 signature and artifact
digest before extracting allowlisted files. No unverified download or automatic
source-build fallback exists. Treat locally selected release directories as
explicit operator version selection; select a current release, not an old one.

The agent runs as an unprivileged system account with systemd sandboxing. Its
token is delivered via LoadCredential, never an ExecStart argument. It cannot
self-update or execute hub commands. Agent upgrades use the local installer.
The hardened hub service also uses local installer upgrades by default;
auto_update_wait is false because its sandbox denies executable replacement.

## Trust and remaining operational responsibilities

A compromised hub can interrupt or redirect traffic, learn timing/destination
metadata, and send hostile bytes to OpenSSH. It cannot authenticate an inner
session without backend credentials or defeat independently pinned host keys.
This assumes patched endpoint software and no separate hub credentials trusted
by the backend. This does not make parser vulnerabilities impossible.

Rotate existing enrollment tokens after repairing legacy world-readable files
or command-line exposure. Deleting the legacy installer does not undo past key
authorizations or permissions on deployed hosts.

Release builds now produce unsigned candidates only. Review the exact artifacts
and sign them with sshhub-sign on an independently trusted signing machine;
publish the artifacts and manifest only afterward. Remove the old repository
SSHHUB_SIGNING_KEY secret and rotate it if exposure is suspected. The source
change cannot revoke copies of a secret already stored in GitHub.

## Development

```sh
go test ./... -race -count=1 -timeout 300s
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Integration tests require root, /usr/sbin/sshd, and /run/sshd. They create
disposable accounts and isolated OpenSSH listeners. They exercise commands,
PTYs and SFTP through the inner SSH connection and test identity/host-key
isolation. No production service needs to be restarted for tests.
