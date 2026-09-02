package e2e

import (
	"context"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
)

// Hub serves TLS; agent connects with the correct pin.
func TestAgentConnectsWithPin(t *testing.T) {
	dir := t.TempDir()
	cert, err := hubtls.LoadOrCreate(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pin := hubtls.Fingerprint(leaf)

	reg := control.NewRegistry()
	srv := control.NewServer(reg, func(tok, req string) (string, bool) {
		if tok == "good-token" {
			return "worker1", true
		}
		return "", false
	}, hubtls.ServerConfig(cert))

	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ListenAndServe(ctx, addr)
	waitListening(t, addr)

	cfg, err := hubtls.ClientConfig("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	sess, backend, err := control.Connect(ctx, addr, "", "good-token", cfg)
	if err != nil {
		t.Fatalf("agent should connect with correct pin: %v", err)
	}
	defer sess.Close()
	if backend != "worker1" {
		t.Fatalf("got backend %q", backend)
	}
	t.Logf("connected over TLS, backend=%s", backend)
}

// An impostor hub (different key) must not be able to harvest the token.
func TestAgentRefusesWrongPin(t *testing.T) {
	dir := t.TempDir()
	cert, _ := hubtls.LoadOrCreate(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), []string{"127.0.0.1"})

	dir2 := t.TempDir()
	other, _ := hubtls.LoadOrCreate(filepath.Join(dir2, "c.pem"), filepath.Join(dir2, "k.pem"), []string{"127.0.0.1"})
	otherLeaf, _ := x509.ParseCertificate(other.Certificate[0])
	wrongPin := hubtls.Fingerprint(otherLeaf)

	reg := control.NewRegistry()
	srv := control.NewServer(reg, func(tok, req string) (string, bool) { return "worker1", true },
		hubtls.ServerConfig(cert))

	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ListenAndServe(ctx, addr)
	waitListening(t, addr)

	cfg, _ := hubtls.ClientConfig("127.0.0.1", wrongPin)
	if _, _, err := control.Connect(ctx, addr, "", "secret-token", cfg); err == nil {
		t.Fatal("SECURITY: agent sent its token to a hub with an unpinned key")
	} else {
		t.Logf("correctly refused: %v", err)
	}
}

// freePort reserves an ephemeral port and returns it, so parallel runs do not
// collide on a hardcoded number.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitListening blocks until addr accepts connections, avoiding a fixed sleep.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s never came up", addr)
}
