package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// GenerateToken generates a cryptographically secure 32-byte URL-safe base64 token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AddBackend adds a new reverse backend and route to the given config file.
// If token is empty, a secure random token is generated.
// If endUser is empty, sessions run as DefaultEndUser (root).
func AddBackend(configPath, id, token, endUser string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("backend id cannot be empty")
	}
	if strings.ContainsAny(endUser, " \t\n/:,") || strings.HasPrefix(endUser, "-") {
		return "", fmt.Errorf("invalid end user %q", endUser)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	if b := cfg.BackendByID(id); b != nil {
		return "", fmt.Errorf("backend %q already exists (token: %s)", id, b.Token)
	}

	if token == "" {
		token, err = GenerateToken()
		if err != nil {
			return "", err
		}
	}

	cfg.Backends = append(cfg.Backends, Backend{
		ID:    id,
		Mode:  "reverse",
		Token: token,
	})

	// Check if a route already covers this backend
	hasRoute := false
	for _, r := range cfg.Routes {
		if r.Match.Hostname == id || r.Hostname == id {
			hasRoute = true
			break
		}
	}

	if !hasRoute {
		newRoute := Route{
			Hostname: id,
			Backend:  id,
			EndUser:  endUser,
		}
		// Insert before any catch-all username: "*" route
		inserted := false
		for i, r := range cfg.Routes {
			if r.Match.Username == "*" || r.Username == "*" {
				cfg.Routes = append(cfg.Routes[:i], append([]Route{newRoute}, cfg.Routes[i:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			cfg.Routes = append(cfg.Routes, newRoute)
		}
	}

	if err := Save(configPath, &cfg); err != nil {
		return "", err
	}

	return token, nil
}

// RemoveBackend removes a backend and its associated routes from the config file.
func RemoveBackend(configPath, id string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	found := false
	newBackends := make([]Backend, 0, len(cfg.Backends))
	for _, b := range cfg.Backends {
		if b.ID == id {
			found = true
			continue
		}
		newBackends = append(newBackends, b)
	}
	if !found {
		return fmt.Errorf("backend %q not found", id)
	}
	cfg.Backends = newBackends

	// Remove routes targeting this backend
	newRoutes := make([]Route, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		if r.Backend == id {
			continue
		}
		newRoutes = append(newRoutes, r)
	}
	cfg.Routes = newRoutes

	return Save(configPath, &cfg)
}

// Save marshals and writes the configuration to path.
func Save(path string, cfg *Config) error {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}
