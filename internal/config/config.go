// Package config defines the sshhub configuration schema and loading.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level sshhub hub configuration.
type Config struct {
	Listen         Listen    `yaml:"listen"`
	HostKey        string    `yaml:"host_key"`
	AuthorizedKeys string    `yaml:"authorized_keys"`
	TLSCert        string    `yaml:"tls_cert"`
	TLSKey         string    `yaml:"tls_key"`
	ControlTokens  []string  `yaml:"control_tokens"`
	Backends       []Backend `yaml:"backends"`
	Routes         []Route   `yaml:"routes"`
}

// Listen holds the addresses the hub binds to.
type Listen struct {
	SSH     string `yaml:"ssh"`
	Control string `yaml:"control"`
}

// Backend describes a single SSH backend server.
type Backend struct {
	ID          string `yaml:"id"`
	Mode        string `yaml:"mode"` // "direct" or "reverse"
	Address     string `yaml:"address"`
	Username    string `yaml:"username"`
	Auth        Auth   `yaml:"auth"`
	HostKey     string `yaml:"host_key"`
	HostKeyFile string `yaml:"host_key_file"`
}

// Auth holds the credentials the hub uses to authenticate to a backend.
type Auth struct {
	PrivateKey string `yaml:"private_key"`
	Password   string `yaml:"password"`
}

// Route maps a matching request to a backend.
type Route struct {
	Match   Match  `yaml:"match"`
	Backend string `yaml:"backend"`
}

// Match is the set of routing predicates. Empty values are wildcards.
type Match struct {
	Username string `yaml:"username"`
	Hostname string `yaml:"hostname"`
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the configuration for structural errors.
func (c *Config) Validate() error {
	if c.Listen.SSH == "" {
		return fmt.Errorf("listen.ssh is required")
	}
	if c.Listen.Control == "" {
		return fmt.Errorf("listen.control is required")
	}
	if c.HostKey == "" {
		return fmt.Errorf("host_key is required")
	}
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}

	seen := make(map[string]bool)
	for i := range c.Backends {
		b := &c.Backends[i]
		if b.ID == "" {
			return fmt.Errorf("backend %d: id is required", i)
		}
		if seen[b.ID] {
			return fmt.Errorf("duplicate backend id %q", b.ID)
		}
		seen[b.ID] = true

		switch b.Mode {
		case "direct":
			if b.Address == "" {
				return fmt.Errorf("backend %q: address is required for direct mode", b.ID)
			}
		case "reverse":
			// reverse backends are reached via the control plane.
		default:
			return fmt.Errorf("backend %q: mode must be \"direct\" or \"reverse\"", b.ID)
		}
	}

	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.Backend == "" {
			return fmt.Errorf("route %d: backend is required", i)
		}
		if !seen[r.Backend] {
			return fmt.Errorf("route %d: unknown backend %q", i, r.Backend)
		}
	}
	return nil
}

// BackendByID returns the backend with the given id, or nil.
func (c *Config) BackendByID(id string) *Backend {
	for i := range c.Backends {
		if c.Backends[i].ID == id {
			return &c.Backends[i]
		}
	}
	return nil
}
