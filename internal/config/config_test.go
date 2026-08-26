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
    mode: direct
    address: "10.0.0.10:22"
  - id: db1
    mode: reverse
routes:
  - match:
      username: "*"
    backend: web1
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
		{"duplicate backend", Config{
			Listen:  Listen{SSH: ":22", Control: ":7000"},
			HostKey: "/k",
			Backends: []Backend{
				{ID: "b", Mode: "reverse"},
				{ID: "b", Mode: "reverse"},
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
