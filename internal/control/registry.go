package control

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// connection is a live agent connection and what the agent reported about
// itself at registration.
//
// Grouped in one struct rather than parallel maps keyed by backend id: separate
// maps have to be kept in step on every register/unregister, and a missed
// delete leaves stale data attributed to a backend that has since reconnected.
type connection struct {
	session *yamux.Session
	// hostKey is the agent's advertised SSH host key, pinned when dialling so a
	// session cannot be served by a different endpoint.
	hostKey string
	// The following are self-reported by the agent at registration. They are
	// informational only -- never used for an authorization decision.
	version string
	os      string
	arch    string
	// connectedAt is when this tunnel was established. It resets on reconnect,
	// so it measures connection uptime, not agent process uptime.
	connectedAt time.Time
	remoteAddr  string
}

// Registry tracks which backend id is reachable over which yamux session.
type Registry struct {
	mu    sync.RWMutex
	conns map[string]*connection
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{conns: make(map[string]*connection)}
}

// BackendStatus is a point-in-time view of a backend, for operator tooling.
type BackendStatus struct {
	Backend     string    `json:"backend"`
	Online      bool      `json:"online"`
	Version     string    `json:"version,omitempty"`
	OS          string    `json:"os,omitempty"`
	Arch        string    `json:"arch,omitempty"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
	HostKey     string    `json:"host_key,omitempty"`
}

// Status returns the current state of every connected backend.
func (r *Registry) Status() []BackendStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]BackendStatus, 0, len(r.conns))
	for id, c := range r.conns {
		out = append(out, BackendStatus{
			Backend:     id,
			Online:      true,
			Version:     c.version,
			OS:          c.os,
			Arch:        c.arch,
			ConnectedAt: c.connectedAt,
			RemoteAddr:  c.remoteAddr,
			HostKey:     c.hostKey,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Backend < out[j].Backend })
	return out
}

// register binds a backend id to a session. It returns an error if the id is
// already registered.
func (r *Registry) register(backend string, s *yamux.Session) error {
	return r.registerConn(backend, s, "", RegisterRequest{}, "")
}

// registerConn binds a backend id to a session, recording the agent's
// advertised host key and self-reported metadata.
func (r *Registry) registerConn(backend string, s *yamux.Session, hostKey string,
	req RegisterRequest, remoteAddr string) error {

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.conns[backend]; ok {
		return fmt.Errorf("backend %q is already registered", backend)
	}
	r.conns[backend] = &connection{
		session:     s,
		hostKey:     hostKey,
		version:     req.Version,
		os:          req.OS,
		arch:        req.Arch,
		connectedAt: time.Now(),
		remoteAddr:  remoteAddr,
	}
	return nil
}

// HostKey returns the advertised SSH host key for a connected backend, or "" if
// the agent did not advertise one.
func (r *Registry) HostKey(backend string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c := r.conns[backend]; c != nil {
		return c.hostKey
	}
	return ""
}

// unregister removes a backend id if it maps to the given session.
func (r *Registry) unregister(backend string, s *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.conns[backend]; ok && cur.session == s {
		delete(r.conns, backend)
	}
}

// Open opens a new stream to the given backend.
func (r *Registry) Open(ctx context.Context, backend string) (net.Conn, error) {
	r.mu.RLock()
	var s *yamux.Session
	if c := r.conns[backend]; c != nil {
		s = c.session
	}
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
