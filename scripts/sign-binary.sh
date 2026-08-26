#!/usr/bin/env bash
# sign-binary.sh: Signs an sshhub-agent binary with an Ed25519 private key.
# This script should be run on the DEVELOPER machine (NOT the public Hub).
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path-to-binary> [private-key-file-or-hex]"
  echo "Example:"
  echo "  $0 ./sshhub-agent ./release.priv"
  exit 1
fi

BIN_PATH="$1"
KEY_ARG="${2:-${SSHHUB_RELEASE_KEY:-}}"

if [[ ! -f "$BIN_PATH" ]]; then
  echo "Error: Binary file not found at $BIN_PATH" >&2
  exit 1
fi

if [[ -z "$KEY_ARG" ]]; then
  if [[ -f "release.priv" ]]; then
    KEY_ARG="release.priv"
  elif [[ -f "scripts/release.priv" ]]; then
    KEY_ARG="scripts/release.priv"
  else
    echo "Error: Private key required. Pass as argument or set SSHHUB_RELEASE_KEY" >&2
    exit 1
  fi
fi

# Load private key hex
if [[ -f "$KEY_ARG" ]]; then
  PRIV_HEX="$(cat "$KEY_ARG" | tr -d '[:space:]')"
else
  PRIV_HEX="$KEY_ARG"
fi

TMP_GO="$(mktemp --suffix=.go)"
trap "rm -f '$TMP_GO'" EXIT

cat > "$TMP_GO" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: signer <binary-path> <private-key-hex>\n")
		os.Exit(1)
	}
	binPath := os.Args[1]
	privHex := strings.TrimSpace(os.Args[2])

	data, err := os.ReadFile(binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read binary: %v\n", err)
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "invalid private key: must be %d bytes hex encoded (got %d)\n", ed25519.PrivateKeySize, len(privBytes))
		os.Exit(1)
	}

	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(privBytes, []byte(shaHex))
	sigHex := hex.EncodeToString(sig)

	sigFile := binPath + ".sig"
	if err := os.WriteFile(sigFile, []byte(sigHex+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write sig file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Binary successfully signed!\n")
	fmt.Printf("  Binary:    %s (%d bytes)\n", binPath, len(data))
	fmt.Printf("  SHA-256:   %s\n", shaHex)
	fmt.Printf("  Signature: %s\n", sigFile)
}
EOF

go run "$TMP_GO" "$BIN_PATH" "$PRIV_HEX"
