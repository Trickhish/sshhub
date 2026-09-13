#!/usr/bin/env bash
set -euo pipefail
umask 077
VERSION="latest"; RELEASE_DIR=""
while (($#)); do case "$1" in --release-dir) RELEASE_DIR="$2"; shift 2;; --version) VERSION="$2"; shift 2;; *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1;; esac; done
[[ $EUID == 0 ]] || { printf 'This installer must run as root\n' >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) exit 1;; esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for DEP in python3 openssl ssh-keygen systemctl; do command -v "$DEP" >/dev/null || { printf 'Required dependency: %s\n' "$DEP" >&2; exit 1; }; done
VERIFIER=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then VERIFIER="$(dirname "$(realpath "${BASH_SOURCE[0]}")")/verify-release.py"; fi
if [[ ! -f "$VERIFIER" ]]; then
  VERIFIER="$TMP/verify-release.py"
  curl --proto '=https' --proto-redir '=https' -fsSL --max-time 60 -o "$VERIFIER" https://raw.githubusercontent.com/Trickhish/sshhub/main/scripts/verify-release.py
fi
[[ "$(sha256sum "$VERIFIER" | cut -d' ' -f1)" == 40de7c41da96e5ddfcc16f1e2f9a4927dcf3500a797776436053cda77a5f6774 ]] || { printf 'Verifier checksum mismatch\n' >&2; exit 1; }
if [[ -z "$RELEASE_DIR" ]]; then
  RELEASE_DIR="$TMP/release"; mkdir -m 700 "$RELEASE_DIR"
  TAG="$VERSION"; [[ "$TAG" == latest ]] && TAG="$(curl -fsSL https://api.github.com/repos/Trickhish/sshhub/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
  [[ "$TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Invalid release tag\n' >&2; exit 1; }
  TAG="v${TAG#v}"; export SSHHUB_EXPECTED_VERSION="$TAG"
  for A in sshhub-linux-$ARCH.tar.gz sshhub-manifest.json; do curl -fsSL -o "$RELEASE_DIR/$A" "https://github.com/Trickhish/sshhub/releases/download/$TAG/$A"; done
fi
python3 "$VERIFIER" "$RELEASE_DIR" "sshhub-linux-$ARCH.tar.gz" "$TMP" sshhub sshhub-ctl
install -d -m 700 /etc/sshhub
if [[ ! -f /etc/sshhub/ssh_host_ed25519_key ]]; then
  ssh-keygen -t ed25519 -N '' -f /etc/sshhub/ssh_host_ed25519_key
fi
# Host keys are never added to any account's authorized_keys.
if [[ ! -f /etc/sshhub/sshhub.yaml ]]; then
  cat > /etc/sshhub/sshhub.yaml <<'EOF'
listen:
  ssh: ":22"
  control: ":7000"
host_key: /etc/sshhub/ssh_host_ed25519_key
auto_update_wait: false
backends: []
jump_users: []
EOF
fi
chmod 600 /etc/sshhub/sshhub.yaml
for BIN in sshhub sshhub-ctl; do
  install -m 755 "$TMP/$BIN" "/usr/local/bin/.$BIN.new"
  mv "/usr/local/bin/.$BIN.new" "/usr/local/bin/$BIN"
done
cat > /etc/systemd/system/sshhub.service <<'EOF'
[Unit]
Description=SSHub forwarding-only gateway
After=network.target
[Service]
ExecStart=/usr/local/bin/sshhub --config /etc/sshhub/sshhub.yaml
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/sshhub /run/sshhub
RuntimeDirectory=sshhub
RuntimeDirectoryMode=0700
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
TasksMax=512
MemoryMax=512M
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/sshhub.service
systemctl daemon-reload
systemctl enable sshhub
systemctl restart sshhub
printf 'Installed. Configure backends and jump_users before connecting.\n'
