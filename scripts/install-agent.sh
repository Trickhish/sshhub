#!/usr/bin/env bash
# install-agent.sh: 1-line installer for SSHub Agent (Client/Node)
set -euo pipefail

REPO="Trickhish/sshhub"
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/sshhub-agent.service"

HUB=""
TOKEN=""
SSHD=""

usage() {
  echo "Usage: $0 --hub <hub-host:7000> --token <token> [--sshd <127.0.0.1:22>]"
  echo "Example:"
  echo "  $0 --hub cdn.srv.dury.dev:7000 --token \"TNgPdS6...\""
  exit 1
}

# Parse flags or positional arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hub)
      HUB="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --sshd)
      SSHD="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      if [[ -z "$HUB" ]]; then
        HUB="$1"
      elif [[ -z "$TOKEN" ]]; then
        TOKEN="$1"
      else
        echo "Unknown argument: $1" >&2
        usage
      fi
      shift
      ;;
  esac
done

if [[ -z "$HUB" || -z "$TOKEN" ]]; then
  echo "Error: Both --hub and --token are required." >&2
  usage
fi

echo "==> Installing SSHub Agent..."

# 1. Check Root
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root (or with sudo)." >&2
  exit 1
fi

# 2. Architecture detection
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# 3. Ensure dependencies
if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl git
  fi
fi

# 4. Install binary
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

INSTALLED=false

RELEASE_URL="https://github.com/${REPO}/releases/latest/download/sshhub-agent-linux-${GOARCH}.tar.gz"
if curl -fsSL -I "$RELEASE_URL" >/dev/null 2>&1; then
  echo "--> Downloading prebuilt agent from GitHub releases..."
  curl -fsSL "$RELEASE_URL" | tar -xz -C "$INSTALL_DIR"
  INSTALLED=true
fi

if [[ "$INSTALLED" = false ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "--> Installing Go compiler..."
    GO_VERSION="1.23.6"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local
    export PATH="/usr/local/go/bin:$PATH"
  fi

  echo "--> Compiling sshhub-agent from source..."
  git clone --depth 1 "https://github.com/${REPO}.git" "${TMP_DIR}/src"
  cd "${TMP_DIR}/src"
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sshhub-agent" ./cmd/sshhub-agent
  cd - >/dev/null
fi

chmod +x "${INSTALL_DIR}/sshhub-agent"

# 5. Create Systemd Service
EXEC_CMD="${INSTALL_DIR}/sshhub-agent --hub ${HUB} --token ${TOKEN}"
if [[ -n "$SSHD" ]]; then
  EXEC_CMD="${EXEC_CMD} --sshd ${SSHD}"
fi

if command -v systemctl >/dev/null 2>&1; then
  echo "--> Configuring systemd service..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SSHub Reverse Agent
After=network.target

[Service]
Type=simple
ExecStart=${EXEC_CMD}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now sshhub-agent
fi

echo ""
echo "✓ SSHub Agent installed and connected to ${HUB}!"
echo ""
