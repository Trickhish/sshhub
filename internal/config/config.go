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
	PublicHost     string    `yaml:"public_host,omitempty"`
	HostKey        string    `yaml:"host_key"`
	AuthorizedKeys string    `yaml:"authorized_keys,omitempty"`
	TLSCert        string    `yaml:"tls_cert,omitempty"`
	TLSKey         string    `yaml:"tls_key,omitempty"`
	ControlTokens  []string  `yaml:"control_tokens,omitempty"`
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
	Token       string `yaml:"token,omitempty"` // per-backend token for reverse mode
	Address     string `yaml:"address,omitempty"`
	Username    string `yaml:"username,omitempty"`
	Auth        *Auth  `yaml:"auth,omitempty"`
	HostKey     string `yaml:"host_key,omitempty"`
	HostKeyFile string `yaml:"host_key_file,omitempty"`
}

// Auth holds the credentials the hub uses to authenticate to a backend.
type Auth struct {
	PrivateKey string `yaml:"private_key,omitempty"`
	Password   string `yaml:"password,omitempty"`
}

// Route maps a matching request to a backend.
// Supports both flat route syntax (hostname, username, backend)
// and nested match blocks (match: { hostname, username }, backend).
type Route struct {
	Match    Match  `yaml:"-"`
	Backend  string `yaml:"backend"`
	Username string `yaml:"username,omitempty"`
	Hostname string `yaml:"hostname,omitempty"`
}

// UnmarshalYAML decodes a route supporting both flat and nested match syntax.
func (r *Route) UnmarshalYAML(value *yaml.Node) error {
	type rawRoute struct {
		Match    Match  `yaml:"match"`
		Backend  string `yaml:"backend"`
		Username string `yaml:"username"`
		Hostname string `yaml:"hostname"`
	}
	var raw rawRoute
	if err := value.Decode(&raw); err != nil {
		return err
	}
	r.Backend = raw.Backend
	r.Username = raw.Username
	r.Hostname = raw.Hostname
	r.Match = raw.Match

	if r.Username != "" && r.Match.Username == "" {
		r.Match.Username = r.Username
	}
	if r.Hostname != "" && r.Match.Hostname == "" {
		r.Match.Hostname = r.Hostname
	}
	if r.Username == "" && r.Match.Username != "" {
		r.Username = r.Match.Username
	}
	if r.Hostname == "" && r.Match.Hostname != "" {
		r.Hostname = r.Match.Hostname
	}
	return nil
}

// MarshalYAML encodes a route using the clean, flat syntax.
func (r Route) MarshalYAML() (interface{}, error) {
	type flatRoute struct {
		Username string `yaml:"username,omitempty"`
		Hostname string `yaml:"hostname,omitempty"`
		Backend  string `yaml:"backend"`
	}
	username := r.Username
	if username == "" && r.Match.Username != "" {
		username = r.Match.Username
	}
	hostname := r.Hostname
	if hostname == "" && r.Match.Hostname != "" {
		hostname = r.Match.Hostname
	}
	return flatRoute{
		Username: username,
		Hostname: hostname,
		Backend:  r.Backend,
	}, nil
}

// Match is the set of routing predicates. Empty values are wildcards.
type Match struct {
	Username string `yaml:"username,omitempty"`
	Hostname string `yaml:"hostname,omitempty"`
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

// Validate checks the configuration for structural errors and normalizes route syntax.
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
	seenTokens := make(map[string]string)
	for i := range c.Backends {
		b := &c.Backends[i]
		if b.ID == "" {
			return fmt.Errorf("backend %d: id is required", i)
		}
		if seen[b.ID] {
			return fmt.Errorf("duplicate backend id %q", b.ID)
		}
		seen[b.ID] = true

		if b.Token != "" {
			if existingID, ok := seenTokens[b.Token]; ok {
				return fmt.Errorf("duplicate token for backends %q and %q", existingID, b.ID)
			}
			seenTokens[b.Token] = b.ID
		}

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
		// Normalize flat syntax into Match
		if r.Username != "" && r.Match.Username == "" {
			r.Match.Username = r.Username
		}
		if r.Hostname != "" && r.Match.Hostname == "" {
			r.Match.Hostname = r.Hostname
		}

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

// BackendByToken returns the reverse backend configured with the given token, or nil.
func (c *Config) BackendByToken(token string) *Backend {
	if token == "" {
		return nil
	}
	for i := range c.Backends {
		b := &c.Backends[i]
		if b.Mode == "reverse" && b.Token == token {
			return b
		}
	}
	return nil
}
