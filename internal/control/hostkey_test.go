package control

import (
	"os"
	"path/filepath"
	"testing"
)

// The agent's host key must survive restarts, otherwise the hub's pin would
// break on every agent restart.
func TestAgentHostKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_host_key")

	a1, err := NewAgentServerWithHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := NewAgentServerWithHostKey(path)
	if err != nil {
		t.Fatal(err)
	}

	if a1.HostKey() == "" {
		t.Fatal("agent advertised an empty host key")
	}
	if a1.HostKey() != a2.HostKey() {
		t.Fatal("agent host key changed across restart; the hub's pin would break")
	}
}

func TestAgentHostKeyIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_host_key")
	if _, err := NewAgentServerWithHostKey(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("agent host key is group/world accessible: %04o", perm)
	}
}

// Ephemeral keys differ per instance -- which is exactly why they cannot be
// pinned, and why the persistent constructor exists.
func TestEphemeralHostKeysDiffer(t *testing.T) {
	a1, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}
	a2, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}
	if a1.HostKey() == a2.HostKey() {
		t.Fatal("expected ephemeral keys to differ")
	}
}
