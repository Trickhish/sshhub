package control

import (
	"testing"
	"time"
)

// Status must report what the agent declared at registration, and only for
// connected backends.
func TestRegistryStatus(t *testing.T) {
	r := NewRegistry()
	if got := r.Status(); len(got) != 0 {
		t.Fatalf("empty registry should report nothing, got %d", len(got))
	}

	req := RegisterRequest{Version: "0.5.1", OS: "linux", Arch: "amd64", HostKey: "ssh-ed25519 AAAA x"}
	if err := r.registerConn("node-a", nil, req.HostKey, req, "10.0.0.5:4242"); err != nil {
		t.Fatal(err)
	}

	got := r.Status()
	if len(got) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(got))
	}
	b := got[0]
	if b.Backend != "node-a" || !b.Online {
		t.Errorf("unexpected: %+v", b)
	}
	if b.Version != "0.5.1" || b.OS != "linux" || b.Arch != "amd64" {
		t.Errorf("agent-reported metadata not surfaced: %+v", b)
	}
	if b.RemoteAddr != "10.0.0.5:4242" {
		t.Errorf("remote addr = %q", b.RemoteAddr)
	}
	if time.Since(b.ConnectedAt) > time.Minute {
		t.Errorf("connectedAt looks wrong: %v", b.ConnectedAt)
	}
}

// Unregistering must remove the metadata too, or a disconnected backend would
// still be reported with stale details.
func TestRegistryStatusClearedOnUnregister(t *testing.T) {
	r := NewRegistry()
	req := RegisterRequest{Version: "0.5.1"}
	if err := r.registerConn("node-a", nil, "", req, "1.2.3.4:1"); err != nil {
		t.Fatal(err)
	}
	r.unregister("node-a", nil)

	if got := r.Status(); len(got) != 0 {
		t.Fatalf("disconnected backend still reported: %+v", got)
	}
	if hk := r.HostKey("node-a"); hk != "" {
		t.Errorf("stale host key retained: %q", hk)
	}
}

// Status must be sorted so output is stable between invocations.
func TestRegistryStatusIsSorted(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"zeta", "alpha", "middle"} {
		if err := r.registerConn(id, nil, "", RegisterRequest{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	got := r.Status()
	for i := 1; i < len(got); i++ {
		if got[i-1].Backend > got[i].Backend {
			t.Fatalf("not sorted: %v", got)
		}
	}
}
