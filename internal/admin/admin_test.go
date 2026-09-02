package admin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/control"
)

func serve(t *testing.T, reg *control.Registry) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go NewServer(reg).ListenAndServe(ctx, sock)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return sock
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket never appeared")
	return ""
}

func TestQueryReportsHubState(t *testing.T) {
	sock := serve(t, control.NewRegistry())

	st, err := Query(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.HubVersion == "" {
		t.Error("hub version should be reported")
	}
	if st.StartedAt.IsZero() {
		t.Error("start time should be reported")
	}
	if len(st.Backends) != 0 {
		t.Errorf("expected no backends, got %d", len(st.Backends))
	}
}

// The socket must be owner-only: it discloses which nodes are reachable and
// from where, which is useful reconnaissance.
func TestSocketIsOwnerOnly(t *testing.T) {
	sock := serve(t, control.NewRegistry())

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket is group/world accessible: %04o", perm)
	}
}

// A socket left behind by an unclean shutdown must not stop the hub from
// serving status after a restart.
func TestStaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewServer(control.NewRegistry()).ListenAndServe(ctx, sock)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := Query(sock); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a stale socket file prevented the admin server from starting")
}

// Querying a missing socket must fail promptly, so operator tooling degrades
// rather than hanging.
func TestQueryMissingSocketFailsFast(t *testing.T) {
	start := time.Now()
	if _, err := Query(filepath.Join(t.TempDir(), "nope.sock")); err == nil {
		t.Fatal("expected an error for a missing socket")
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Errorf("took %s; operator tooling would appear to hang", elapsed)
	}
}
