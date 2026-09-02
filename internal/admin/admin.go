// Package admin exposes hub state to local operator tooling over a Unix socket.
//
// A Unix socket rather than a TCP listener: the hub is internet-facing, and
// runtime state (which nodes are online, their versions and addresses) is
// exactly the reconnaissance an attacker wants. A socket in the filesystem
// cannot be reached from the network at all, and access control comes from file
// permissions rather than from authentication code that could be got wrong.
//
// The socket is read-only. It reports state; it cannot change configuration or
// disconnect a backend. Adding mutating commands later would need a considered
// authorization story, since anything that can reach the socket is already root.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/version"
)

// DefaultSocketPath is where the hub exposes its admin socket.
const DefaultSocketPath = "/run/sshhub/admin.sock"

// Status is the hub's reply to a status request.
type Status struct {
	HubVersion string                  `json:"hub_version"`
	StartedAt  time.Time               `json:"started_at"`
	Backends   []control.BackendStatus `json:"backends"`
}

// Server serves hub status on a Unix socket.
type Server struct {
	registry  *control.Registry
	startedAt time.Time
}

// NewServer builds an admin server reporting on the given registry.
func NewServer(registry *control.Registry) *Server {
	return &Server{registry: registry, startedAt: time.Now()}
}

// ListenAndServe serves on path until ctx is cancelled.
//
// A stale socket from an unclean shutdown is removed first, otherwise bind
// fails and the hub would lose status reporting after a crash.
func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", path, err)
	}

	// Owner-only. The socket exposes which nodes are reachable and from where,
	// so it should not be readable by other local users.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(path)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	// A client that connects and never reads must not pin the goroutine.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	status := Status{
		HubVersion: version.Version,
		StartedAt:  s.startedAt,
		Backends:   s.registry.Status(),
	}
	if err := json.NewEncoder(conn).Encode(status); err != nil {
		log.Printf("admin: write status: %v", err)
	}
}

// Query reads hub status from the admin socket. Used by sshhub-ctl.
func Query(path string) (*Status, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var st Status
	if err := json.NewDecoder(conn).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &st, nil
}
