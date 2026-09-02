package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddAndRemoveBackend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshhub.yaml")
	initialData := `
listen:
  ssh: ":22"
  control: ":7000"
host_key: "/tmp/key"
backends:
  - id: cidev
    mode: reverse
    token: "token-cidev"
routes:
  - hostname: "cidev"
    backend: cidev
  - username: "*"
    backend: cidev
`
	if err := os.WriteFile(path, []byte(initialData), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Add new backend worker1
	token, err := AddBackend(path, "worker1", "", "")
	if err != nil {
		t.Fatalf("AddBackend failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty generated token")
	}

	// Verify loaded config
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load config failed: %v", err)
	}
	if len(cfg.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(cfg.Backends))
	}
	b := cfg.BackendByID("worker1")
	if b == nil || b.Token != token {
		t.Fatalf("expected backend worker1 with token %s, got %+v", token, b)
	}

	// Check route was added before catch-all
	if len(cfg.Routes) != 3 {
		t.Fatalf("expected 3 routes, got %d: %+v", len(cfg.Routes), cfg.Routes)
	}
	if cfg.Routes[1].Match.Hostname != "worker1" || cfg.Routes[1].Backend != "worker1" {
		t.Fatalf("unexpected route at index 1: %+v", cfg.Routes[1])
	}
	if cfg.Routes[2].Match.Username != "*" {
		t.Fatalf("expected catch-all at the end, got %+v", cfg.Routes[2])
	}

	// 2. Duplicate add should fail
	if _, err := AddBackend(path, "worker1", "", ""); err == nil {
		t.Fatal("expected error adding duplicate backend")
	}

	// 3. Remove backend
	if err := RemoveBackend(path, "worker1"); err != nil {
		t.Fatalf("RemoveBackend failed: %v", err)
	}

	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load config failed: %v", err)
	}
	if len(cfg.Backends) != 1 || cfg.Backends[0].ID != "cidev" {
		t.Fatalf("expected only cidev backend left, got %+v", cfg.Backends)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes left, got %d", len(cfg.Routes))
	}
}
