#!/usr/bin/env bash
# install-agent.sh: 1-line installer and updater for SSHub Agent (Client/Node)
set -euo pipefail

REPO="Trickhish/sshhub"
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/sshhub-agent.service"

HUB=""
TOKEN=""
SSHD=""
REBUILD=false
VERSION="latest"

usage() {
  echo "Usage:"
  echo "  Fresh install: $0 --hub <hub-host:7000> --token <token> [options]"
  echo "  Update:        $0 [options]"
  echo ""
  echo "Options:"
  echo "  --hub <host:port>     SSHub Hub control listener address (e.g. hub.example.com:7000)"
  echo "  --token <token>       Authentication token generated on the Hub"
  echo "  --sshd <host:port>    Target OpenSSH daemon address (default: embedded native agent)"
  echo "  --build, --rebuild    Force compilation from source instead of downloading release"
  echo "  --version <vX.Y.Z>    Target release version (default: latest stable release)"
  echo ""
  echo "Example:"
  echo "  curl -sSL https://raw.githubusercontent.com/${REPO}/main/scripts/install-agent.sh | sudo bash -s -- --hub hub.example.com:7000 --token \"<token>\""
  exit 1
}

# Helper to extract flag values from existing service file
extract_flag() {
  local flag="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    return
  fi
  sed -n "s/.*--${flag}[ =][\"'[:space:]]*\([^\"'[:space:]]*\).*/\1/p" "$file" | head -n 1
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

# If flags not provided, check for existing installation configuration
if [[ -f "$SERVICE_FILE" ]]; then
  if [[ -z "$HUB" ]]; then
    HUB="$(extract_flag "hub" "$SERVICE_FILE")"
  fi
  if [[ -z "$TOKEN" ]]; then
    TOKEN="$(extract_flag "token" "$SERVICE_FILE")"
  fi
  if [[ -z "$SSHD" ]]; then
    SSHD="$(extract_flag "sshd" "$SERVICE_FILE")"
  fi
  if [[ -n "$HUB" && -n "$TOKEN" ]]; then
    echo "--> Detected existing agent config: hub=${HUB}"
  fi
fi

# If still missing and interactive, prompt the user
if [[ -z "$HUB" && -t 0 ]]; then
  read -rp "Enter SSHub Hub address (e.g. hub.example.com:7000): " HUB
fi

if [[ -z "$TOKEN" && -t 0 ]]; then
  read -rp "Enter Agent registration token: " TOKEN
fi

# If still missing, fail with a clear error
if [[ -z "$HUB" ]]; then
  echo "Error: Hub address is required. Specify with --hub <hub-host:7000>" >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "Error: Registration token is required. Specify with --token <token>" >&2
  exit 1
fi

echo "==> Installing / Updating SSHub Agent..."

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
    apt-get update -qq && apt-get install -y -qq curl tar
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl tar
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl tar
  fi
fi

# 4. Stop service before binary replacement if currently running
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  if systemctl is-active --quiet sshhub-agent; then
    systemctl stop sshhub-agent || true
  fi
fi

# 5. Install / Update binary
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

INSTALLED=false

if [[ "$REBUILD" = false ]]; then
  ASSET_NAME="sshhub-agent-linux-${GOARCH}.tar.gz"
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  if [[ "$VERSION" != "latest" ]]; then
    TAG="$VERSION"
    [[ ! "$TAG" =~ ^v ]] && TAG="v${TAG}"
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
  fi

  echo "--> Fetching latest release binary from GitHub..."
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

  echo "--> Compiling sshhub-agent from source..."
  git clone --depth 1 "https://github.com/${REPO}.git" "${TMP_DIR}/src"
  cd "${TMP_DIR}/src"
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sshhub-agent" ./cmd/sshhub-agent
  cd - >/dev/null
fi

chmod +x "${INSTALL_DIR}/sshhub-agent"

# 6. Create or update Systemd Service
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
echo "✓ SSHub Agent installed/updated and connected to ${HUB}!"
echo ""
