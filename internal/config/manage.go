package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
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
	if endUser != "" {
		return "", fmt.Errorf("--end-user removed: OpenSSH authenticates the inner client's chosen account")
	}
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
		return "", fmt.Errorf("backend %q already exists", id)
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

	// Transport grants require explicit jump_users configuration.

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
	for i := range cfg.JumpUsers {
		var kept []string
		for _, b := range cfg.JumpUsers[i].Backends {
			if b != id {
				kept = append(kept, b)
			}
		}
		cfg.JumpUsers[i].Backends = kept
	}

	return Save(configPath, &cfg)
}

// Save marshals and writes the configuration to path.
func Save(path string, cfg *Config) error {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".sshhub-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}
