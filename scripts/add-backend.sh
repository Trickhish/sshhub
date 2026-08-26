#!/usr/bin/env bash
# add-backend.sh: Generates a token, registers a backend in sshhub.yaml, and reloads sshhub.
set -euo pipefail

CONFIG_FILE="${SSHHUB_CONFIG:-/etc/sshhub/sshhub.yaml}"
HUB_ADDR="${SSHHUB_HUB:-}"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backend-id> [hub-address:7000]"
  echo "Example: $0 worker1 cdn.srv.dury.dev:7000"
  exit 1
fi

BACKEND_ID="$1"
if [[ $# -ge 2 ]]; then
  HUB_ADDR="$2"
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  if [[ -f "sshhub.yaml" ]]; then
    CONFIG_FILE="sshhub.yaml"
  else
    echo "Error: Configuration file not found at $CONFIG_FILE" >&2
    exit 1
  fi
fi

# Generate 32-byte secure base64 token
TOKEN=$(openssl rand -base64 32 | tr -d '\n' | tr '/+' '_-' | tr -d '=')

if grep -q "id: \?[\"']\?${BACKEND_ID}[\"']\?" "$CONFIG_FILE"; then
  echo "Error: Backend '$BACKEND_ID' already exists in $CONFIG_FILE" >&2
  exit 1
fi

# Append backend entry before routes: or at end of backends
# If yq is available, use it, otherwise use python3/awk/sed
if command -v python3 >/dev/null 2>&1; then
  python3 - <<EOF
import yaml, sys

with open("$CONFIG_FILE", "r") as f:
    cfg = yaml.safe_load(f) or {}

backends = cfg.get("backends", [])
backends.append({
    "id": "$BACKEND_ID",
    "mode": "reverse",
    "token": "$TOKEN"
})
cfg["backends"] = backends

routes = cfg.get("routes", [])
routes.insert(0, {
    "hostname": "$BACKEND_ID",
    "backend": "$BACKEND_ID"
})
cfg["routes"] = routes

with open("$CONFIG_FILE", "w") as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
EOF
else
  # Fallback: append backend definition directly
  cat >> "$CONFIG_FILE" <<EOF

# Added backend: $BACKEND_ID
  - id: $BACKEND_ID
    mode: reverse
    token: "$TOKEN"
EOF
fi

# Restart sshhub service if systemctl is available
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sshhub; then
  systemctl restart sshhub
fi

echo ""
echo "✓ Backend \"$BACKEND_ID\" successfully added to $CONFIG_FILE"
echo ""
echo "Generated Token:"
echo "  $TOKEN"
echo ""
echo "To start the agent on \"$BACKEND_ID\", run:"
if [[ -n "$HUB_ADDR" ]]; then
  echo "  sshhub-agent --hub $HUB_ADDR --token \"$TOKEN\""
else
  echo "  sshhub-agent --hub <hub-host>:7000 --token \"$TOKEN\""
fi
echo ""
echo "To connect from your client:"
echo "  ssh $BACKEND_ID@<hub-domain>"
echo "  ssh root@$BACKEND_ID@<hub-domain>"
echo ""
