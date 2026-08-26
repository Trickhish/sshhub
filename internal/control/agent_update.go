package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

// RequestAndApplyUpdate opens an update stream with the hub, receives the new binary,
// verifies its checksum and cryptographic Ed25519 signature, replaces the local executable,
// and restarts the process.
func RequestAndApplyUpdate(session *yamux.Session) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open update stream: %w", err)
	}
	defer stream.Close()

	header, err := ReadUpdateHeader(stream)
	if err != nil {
		return fmt.Errorf("read update header: %w", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/sshhub-agent"
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		execPath = "/usr/local/bin/sshhub-agent"
	}

	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, "sshhub-agent-update-*")
	if err != nil {
		// Fallback to /tmp if current directory is not writable
		tmpFile, err = os.CreateTemp("/tmp", "sshhub-agent-update-*")
		if err != nil {
			return fmt.Errorf("create temp binary: %w", err)
		}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	log.Printf("agent: receiving update to version %s (%d bytes)...", header.Version, header.Size)
	n, err := io.CopyN(writer, stream, header.Size)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("download update: %w", err)
	}
	tmpFile.Close()

	if n != header.Size {
		return fmt.Errorf("incomplete download: got %d bytes, want %d", n, header.Size)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if header.SHA256 != "" && actualSHA != header.SHA256 {
		return fmt.Errorf("checksum mismatch: got %s, want %s", actualSHA, header.SHA256)
	}

	// Cryptographic Ed25519 signature verification against trusted Developer Public Key
	if version.UpdatePublicKeyHex != "" {
		if header.Signature == "" {
			return fmt.Errorf("security error: binary update is missing required Ed25519 cryptographic signature")
		}

		trustedPubBytes, err := hex.DecodeString(version.UpdatePublicKeyHex)
		if err != nil || len(trustedPubBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid trusted public key format: %v", err)
		}

		sigBytes, err := hex.DecodeString(header.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature encoding: %v", err)
		}

		// Verify signature over the binary SHA256 string
		if !ed25519.Verify(trustedPubBytes, []byte(actualSHA), sigBytes) {
			return fmt.Errorf("SECURITY ALERT: Cryptographic signature verification failed! Refusing to install untrusted update")
		}
		log.Printf("agent: ✓ Cryptographic Ed25519 signature verified successfully")
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod binary: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		// If rename fails (e.g. cross-device), copy bytes directly
		if err := copyFile(tmpPath, execPath); err != nil {
			return fmt.Errorf("replace executable %s: %w", execPath, err)
		}
	}

	log.Printf("agent: binary updated to version %s successfully at %s! Restarting...", header.Version, execPath)

	// Attempt systemd restart if managed by systemd
	if err := exec.Command("systemctl", "restart", "sshhub-agent").Start(); err == nil {
		os.Exit(0)
	}

	// Fallback to in-place exec restart
	return syscall.Exec(execPath, os.Args, os.Environ())
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
