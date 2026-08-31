package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
listen:
  ssh: ":2222"
  control: ":7000"
host_key: "/tmp/key"
backends:
  - id: web1
    mode: reverse
    token: "token-web1"
  - id: db1
    mode: reverse
    token: "token-db1"
routes:
  - hostname: "web1"
    backend: web1
  - username: "*"
    backend: db1
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.SSH != ":2222" || c.Listen.Control != ":7000" {
		t.Fatalf("unexpected listen: %+v", c.Listen)
	}
	if len(c.Backends) != 2 || c.Backends[1].Mode != "reverse" {
		t.Fatalf("unexpected backends: %+v", c.Backends)
	}
	if b := c.BackendByToken("token-db1"); b == nil || b.ID != "db1" {
		t.Fatalf("expected backend db1 for token-db1, got %+v", b)
	}
	if len(c.Routes) != 2 || c.Routes[0].Match.Hostname != "web1" {
		t.Fatalf("unexpected normalized routes: %+v", c.Routes)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing ssh listen", Config{Listen: Listen{Control: ":7000"}}},
		{"missing host key", Config{Listen: Listen{SSH: ":22", Control: ":7000"}}},
		{"bad mode", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b", Mode: "bogus"},
			},
		}},
		{"direct mode rejected", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b", Mode: "direct", Address: "10.0.0.1:22"},
			},
		}},
		{"duplicate backend", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b", Mode: "reverse"},
				{ID: "b", Mode: "reverse"},
			},
		}},
		{"duplicate token", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b1", Mode: "reverse", Token: "tok"},
				{ID: "b2", Mode: "reverse", Token: "tok"},
			},
		}},
		{"unknown route backend", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b", Mode: "reverse"},
			},
			Routes: []Route{
				{Match: Match{Username: "*"}, Backend: "nope"},
			},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
