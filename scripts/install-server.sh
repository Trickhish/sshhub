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
REBUILD=false
VERSION="latest"

usage() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --ssh-port <port>     SSH listener port (default: :22)"
  echo "  --control-port <port> Control plane listener port (default: :7000)"
  echo "  --build, --rebuild    Force compilation from source instead of downloading release"
  echo "  --version <vX.Y.Z>    Target release version (default: latest stable release)"
  echo ""
  echo "Example:"
  echo "  curl -sSL https://raw.githubusercontent.com/${REPO}/main/scripts/install-server.sh | sudo bash"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-port)
      SSH_PORT="$2"
      shift 2
      ;;
    --control-port)
      CONTROL_PORT="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --build|--rebuild|--from-source)
      REBUILD=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      ;;
  esac
done

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

# 3. Ensure dependencies (curl, git, tar)
if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq curl tar git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl tar git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl tar git
  fi
fi

# 4. Stop service before binary replacement if currently running
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  if systemctl is-active --quiet sshhub; then
    systemctl stop sshhub || true
  fi
fi

# 5. Install binaries
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

INSTALLED=false

if [[ "$REBUILD" = false ]]; then
  ASSET_NAME="sshhub-linux-${GOARCH}.tar.gz"
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  if [[ "$VERSION" != "latest" ]]; then
    TAG="$VERSION"
    [[ ! "$TAG" =~ ^v ]] && TAG="v${TAG}"
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
  fi

  echo "--> Fetching latest release binaries from GitHub..."
  DOWNLOAD_URL=""
  if RELEASE_JSON="$(curl -fsSL -H "User-Agent: sshhub-installer" "$API_URL" 2>/dev/null)"; then
    DOWNLOAD_URL="$(echo "$RELEASE_JSON" | grep -o "\"browser_download_url\":[[:space:]]*\"[^\"]*${ASSET_NAME}[^\"]*\"" | head -n 1 | cut -d'"' -f4 || true)"
  fi

  if [[ -z "$DOWNLOAD_URL" ]]; then
    if [[ "$VERSION" == "latest" ]]; then
      DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
    else
      DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"
    fi
  fi

  if curl -fsSL -H "User-Agent: sshhub-installer" "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR" 2>/dev/null; then
    echo "✓ Downloaded and installed release from GitHub!"
    INSTALLED=true
  fi
fi

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

# 6. Create Configuration Directory & Host Key
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$HOST_KEY" ]]; then
  echo "--> Generating SSH host key at $HOST_KEY..."
  ssh-keygen -t ed25519 -N "" -f "$HOST_KEY" >/dev/null
fi
if [[ -f "${HOST_KEY}.pub" ]]; then
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  PUB_CONTENT=$(cat "${HOST_KEY}.pub")
  if ! grep -Fxq "$PUB_CONTENT" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "$PUB_CONTENT" >> /root/.ssh/authorized_keys
  fi
fi

# 7. Create default sshhub.yaml if missing
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

# 8. Create Systemd Service
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
