// Package config defines the sshhub configuration schema and loading.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level sshhub hub configuration.
type Config struct {
	Listen        Listen    `yaml:"listen"`
	PublicHost    string    `yaml:"public_host,omitempty"`
	HostKey       string    `yaml:"host_key"`
	TLSCert       string    `yaml:"tls_cert,omitempty"`
	TLSKey        string    `yaml:"tls_key,omitempty"`
	ControlTokens []string  `yaml:"control_tokens,omitempty"`
	Backends      []Backend `yaml:"backends"`
	Routes        []Route   `yaml:"routes"`
}

// Listen holds the addresses the hub binds to.
type Listen struct {
	SSH     string `yaml:"ssh"`
	Control string `yaml:"control"`
}

// Backend describes a single agent-backed backend server.
type Backend struct {
	ID    string `yaml:"id"`
	Mode  string `yaml:"mode"`            // must be "reverse" (agent-backed)
	Token string `yaml:"token,omitempty"` // per-backend registration token

	// Username is no longer honoured. The Unix account a session runs as is
	// determined solely by the matched route's end_user (defaulting to root).
	// A config still carrying this field is REJECTED by Validate rather than
	// silently ignored: ignoring it would quietly escalate a session that used
	// to run as an unprivileged account into running as root.
	Username string `yaml:"username,omitempty"`

	// HostKey/HostKeyFile pin the agent's SSH host key. Not yet enforced.
	HostKey     string `yaml:"host_key,omitempty"`
	HostKeyFile string `yaml:"host_key_file,omitempty"`
}

// Route maps a matching request to a backend.
// Supports both flat route syntax (hostname, username, backend)
// and nested match blocks (match: { hostname, username }, backend).
//
// Username/Hostname are ROUTING IDENTIFIERS matched against the client's login
// string; they need not correspond to any Unix account. EndUser is the Unix
// account the session actually runs as on the backend, and comes only from this
// config -- never from client input.
type Route struct {
	Match    Match  `yaml:"-"`
	Backend  string `yaml:"backend"`
	Username string `yaml:"username,omitempty"`
	Hostname string `yaml:"hostname,omitempty"`
	EndUser  string `yaml:"end_user,omitempty"`
}

// UnmarshalYAML decodes a route supporting both flat and nested match syntax.
func (r *Route) UnmarshalYAML(value *yaml.Node) error {
	type rawRoute struct {
		Match    Match  `yaml:"match"`
		Backend  string `yaml:"backend"`
		Username string `yaml:"username"`
		Hostname string `yaml:"hostname"`
		EndUser  string `yaml:"end_user"`
	}
	var raw rawRoute
	if err := value.Decode(&raw); err != nil {
		return err
	}
	r.Backend = raw.Backend
	r.Username = raw.Username
	r.Hostname = raw.Hostname
	r.EndUser = raw.EndUser
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
		EndUser  string `yaml:"end_user,omitempty"`
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
		EndUser:  r.EndUser,
		Backend:  r.Backend,
	}, nil
}

// DefaultEndUser is the Unix account a session runs as when the matched route
// does not specify end_user.
const DefaultEndUser = "root"

// ResolvedEndUser returns the Unix account this route's sessions run as.
func (r Route) ResolvedEndUser() string {
	if r.EndUser != "" {
		return r.EndUser
	}
	return DefaultEndUser
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
		case "reverse":
			// reverse backends are reached via the control plane (sshhub-agent).
		case "direct":
			return fmt.Errorf("backend %q: \"direct\" mode is no longer supported for security reasons; "+
				"run sshhub-agent on the target and use mode \"reverse\" instead", b.ID)
		default:
			return fmt.Errorf("backend %q: mode must be \"reverse\"", b.ID)
		}

		// Reject rather than ignore: silently dropping username would promote a
		// session that previously ran as an unprivileged account to root.
		if b.Username != "" {
			return fmt.Errorf("backend %q: \"username\" is no longer supported; "+
				"set \"end_user: %s\" on the route(s) targeting this backend instead",
				b.ID, b.Username)
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

		// end_user names a Unix account on the backend. The hub cannot verify it
		// exists (only the agent can), but it can reject values that could never
		// be a valid account name and would otherwise fail confusingly at runtime.
		if r.EndUser != "" {
			if strings.ContainsAny(r.EndUser, " \t\n/:,") {
				return fmt.Errorf("route %d: invalid end_user %q", i, r.EndUser)
			}
			if strings.HasPrefix(r.EndUser, "-") {
				return fmt.Errorf("route %d: invalid end_user %q", i, r.EndUser)
			}
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
