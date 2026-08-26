#!/usr/bin/env bash
# install-server.sh: 1-line installer for SSHub Gateway Server
set -euo pipefail

REPO="Trickhish/sshhub"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sshhub"
CONFIG_FILE="${CONFIG_DIR}/sshhub.yaml"
HOST_KEY="${CONFIG_DIR}/ssh_host_ed25519_key"
SERVICE_FILE="/etc/systemd/system/sshhub.service"

SSH_PORT="${SSH_PORT:-:22}"
CONTROL_PORT="${CONTROL_PORT:-:7000}"

echo "==> Installing SSHub Gateway..."

# 1. Check Root
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root (or with sudo)." >&2
  exit 1
fi

# 2. Architecture & OS detection
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# 3. Ensure dependencies (curl, git)
if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl git
  fi
fi

# 4. Install binaries
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

INSTALLED=false

# Try downloading release binary if available
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/sshhub-linux-${GOARCH}.tar.gz"
if curl -fsSL -I "$RELEASE_URL" >/dev/null 2>&1; then
  echo "--> Downloading prebuilt binaries from GitHub releases..."
  curl -fsSL "$RELEASE_URL" | tar -xz -C "$INSTALL_DIR"
  INSTALLED=true
fi

# If no prebuilt binary, build from source using Go
if [[ "$INSTALLED" = false ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "--> Installing Go compiler..."
    GO_VERSION="1.23.6"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local
    export PATH="/usr/local/go/bin:$PATH"
  fi

  echo "--> Compiling sshhub and sshhub-ctl from source..."
  git clone --depth 1 "https://github.com/${REPO}.git" "${TMP_DIR}/src"
  cd "${TMP_DIR}/src"
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sshhub" ./cmd/sshhub
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sshhub-ctl" ./cmd/sshhub-ctl
  cd - >/dev/null
fi

chmod +x "${INSTALL_DIR}/sshhub" "${INSTALL_DIR}/sshhub-ctl"

# 5. Create Configuration Directory & Host Key
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$HOST_KEY" ]]; then
  echo "--> Generating SSH host key at $HOST_KEY..."
  ssh-keygen -t ed25519 -N "" -f "$HOST_KEY" >/dev/null
fi

# 6. Create default sshhub.yaml if missing
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "--> Creating default configuration at $CONFIG_FILE..."
  cat > "$CONFIG_FILE" <<EOF
listen:
  ssh: "${SSH_PORT}"
  control: "${CONTROL_PORT}"

host_key: "${HOST_KEY}"

backends: []

routes: []
EOF
fi

# 7. Create Systemd Service
if command -v systemctl >/dev/null 2>&1; then
  echo "--> Configuring systemd service..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SSHub Central Gateway
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sshhub --config ${CONFIG_FILE}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now sshhub
fi

echo ""
echo "✓ SSHub Gateway installed and running!"
echo ""
echo "Next steps:"
echo "  1. Add your first backend node:"
echo "     sshhub-ctl add <backend-id>"
echo ""
echo "  2. View all backends:"
echo "     sshhub-ctl list"
echo ""
