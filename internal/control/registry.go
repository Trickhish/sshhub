package control

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
)

// Registry tracks which backend id is reachable over which yamux session.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*yamux.Session
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]*yamux.Session)}
}

// register binds a backend id to a session. It returns an error if the id is
// already registered.
func (r *Registry) register(backend string, s *yamux.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[backend]; ok {
		return fmt.Errorf("backend %q is already registered", backend)
	}
	r.sessions[backend] = s
	return nil
}

// unregister removes a backend id if it maps to the given session.
func (r *Registry) unregister(backend string, s *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[backend]; ok && cur == s {
		delete(r.sessions, backend)
	}
}

// Open opens a new stream to the given backend.
func (r *Registry) Open(ctx context.Context, backend string) (net.Conn, error) {
	r.mu.RLock()
	s := r.sessions[backend]
	r.mu.RUnlock()
	if s == nil {
		return nil, fmt.Errorf("backend %q is not connected", backend)
	}

	stream, err := s.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream to %q: %w", backend, err)
	}
	return stream, nil
}
