#!/usr/bin/env bash
# Install a locally downloaded, signature-verified release. No curl|tar fallback.
set -euo pipefail
umask 077
HUB=""; PIN=""; TOKEN_FILE=""; RELEASE_DIR=""; VERSION="latest"; TOKEN=""; SSHD="127.0.0.1:22"
while (($#)); do
  case "$1" in
    --hub) HUB="$2"; shift 2;;
    --hub-pin) PIN="$2"; shift 2;;
    --token-file) TOKEN_FILE="$2"; shift 2;;
    --release-dir) RELEASE_DIR="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --sshd) SSHD="$2"; shift 2;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1;;
  esac
done
[[ $EUID == 0 && -n "$HUB" && -n "$PIN" ]] || {
  printf 'Usage (root): install-agent.sh --hub HOST:PORT --hub-pin PIN [--token TOKEN | --token-file FILE] [--version vX.Y.Z]\n' >&2; exit 1;
}
[[ "$HUB" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ && "$PIN" =~ ^sha256:[a-zA-Z0-9+/]+=*$ ]] || { printf 'Invalid hub or pin (use a DNS name or IPv4 address)\n' >&2; exit 1; }
[[ "$SSHD" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { printf 'Installer requires IPv4 loopback sshd\n' >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) exit 1;; esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for DEP in python3 openssl systemctl; do command -v "$DEP" >/dev/null || { printf 'Required dependency: %s\n' "$DEP" >&2; exit 1; }; done
VERIFIER=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then VERIFIER="$(dirname "$(realpath "${BASH_SOURCE[0]}")")/verify-release.py"; fi
if [[ ! -f "$VERIFIER" ]]; then
  VERIFIER="$TMP/verify-release.py"
  curl --proto '=https' --proto-redir '=https' -fsSL --max-time 60 -o "$VERIFIER" https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/verify-release.py
fi
[[ "$(sha256sum "$VERIFIER" | cut -d' ' -f1)" == 40de7c41da96e5ddfcc16f1e2f9a4927dcf3500a797776436053cda77a5f6774 ]] || { printf 'Verifier checksum mismatch\n' >&2; exit 1; }
if [[ -z "$TOKEN_FILE" && -n "$TOKEN" ]]; then TOKEN_FILE="$TMP/token"; printf '%s\n' "$TOKEN" > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"; fi
[[ -f "$TOKEN_FILE" ]] || { printf 'A token or token file is required\n' >&2; exit 1; }
if [[ -z "$RELEASE_DIR" ]]; then
  RELEASE_DIR="$TMP/release"; mkdir -m 700 "$RELEASE_DIR"
  TAG="$VERSION"; [[ "$TAG" == latest ]] && TAG="$(curl -fsSL https://api.github.com/repos/Trickhish/sshhub/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
  [[ "$TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Invalid release tag\n' >&2; exit 1; }
  TAG="v${TAG#v}"; export SSHHUB_EXPECTED_VERSION="$TAG"
  curl -fsSL -o "$RELEASE_DIR/sshhub-agent-linux-$ARCH.tar.gz" "https://github.com/Trickhish/sshhub/releases/download/$TAG/sshhub-agent-linux-$ARCH.tar.gz"
  curl -fsSL -o "$RELEASE_DIR/sshhub-manifest.json" "https://github.com/Trickhish/sshhub/releases/download/$TAG/sshhub-manifest.json"
fi
python3 "$VERIFIER" "$RELEASE_DIR" "sshhub-agent-linux-$ARCH.tar.gz" "$TMP" sshhub-agent
command -v sshd >/dev/null || { printf 'Install and configure OpenSSH server first\n' >&2; exit 1; }
id sshhub-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sshhub-agent
install -d -m 700 /etc/sshhub-agent
install -m 600 "$TOKEN_FILE" /etc/sshhub-agent/token.new
mv /etc/sshhub-agent/token.new /etc/sshhub-agent/token
install -m 755 "$TMP/sshhub-agent" /usr/local/bin/.sshhub-agent.new
mv /usr/local/bin/.sshhub-agent.new /usr/local/bin/sshhub-agent
cat > /etc/systemd/system/sshhub-agent.service <<EOF
[Unit]
Description=SSHub forwarding agent
After=network.target
[Service]
User=sshhub-agent
Group=sshhub-agent
LoadCredential=token:/etc/sshhub-agent/token
ExecStart=/usr/local/bin/sshhub-agent --hub ${HUB} --hub-pin ${PIN} --token-file %d/token --sshd ${SSHD}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
TasksMax=128
MemoryMax=256M
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/sshhub-agent.service
systemctl daemon-reload
systemctl enable sshhub-agent
systemctl restart sshhub-agent
printf 'Installed forwarding-only agent. Verify backend host keys independently on each SSH client.\n'
