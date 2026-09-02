package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

// TokenResolver validates a registration token and resolves it to a backend ID.
type TokenResolver func(token, requestedBackend string) (backendID string, ok bool)

// Server is the hub side of the control plane.
type Server struct {
	registry     *Registry
	resolveToken TokenResolver
	tlsConfig    *tls.Config
}

// NewServer builds a Server. resolveToken resolves a presented token to an assigned backend ID.
func NewServer(registry *Registry, resolveToken TokenResolver, tlsConfig *tls.Config) *Server {
	return &Server{
		registry:     registry,
		resolveToken: resolveToken,
		tlsConfig:    tlsConfig,
	}
}

// ListenAndServe accepts agent connections until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	log.Printf("control plane listening on %s", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
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
		go s.handleConn(conn)
	}
}

// handleConn wraps an agent connection in a yamux session and processes its
// registration stream.
func (s *Server) handleConn(conn net.Conn) {
	session, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return
	}

	backend, err := s.register(session)
	if err != nil {
		log.Printf("control: %v", err)
		session.Close()
		return
	}

	// A second agent presenting the same token must not silently displace or
	// shadow the first: previously this error was discarded, so the hub logged
	// "connected" for a session that was never in the registry.
	if err := s.registry.register(backend, session); err != nil {
		log.Printf("control: refusing registration for %q: %v", backend, err)
		session.Close()
		return
	}
	log.Printf("backend %q connected", backend)

	// Remove the backend when the session drops.
	<-session.CloseChan()
	s.registry.unregister(backend, session)
	log.Printf("backend %q disconnected", backend)
}

// register waits for the agent's registration stream and validates it.
func (s *Server) register(session *yamux.Session) (string, error) {
	stream, err := session.AcceptStream()
	if err != nil {
		return "", fmt.Errorf("accept registration stream: %w", err)
	}
	defer stream.Close()

	req, err := ReadRegister(stream)
	if err != nil {
		return "", fmt.Errorf("read register request: %w", err)
	}
	if req.Token == "" {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "token is required"})
		return "", &RegistrationError{Message: "token is required"}
	}

	backendID, ok := s.resolveToken(req.Token, req.Backend)
	if !ok {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "invalid token"})
		return "", &RegistrationError{Message: "invalid token"}
	}

	updateAvailable := req.Version != "" && req.Version != version.Version

	resp := RegisterResponse{
		OK:              true,
		Backend:         backendID,
		UpdateAvailable: updateAvailable,
		LatestVersion:   version.Version,
	}

	if err := WriteResponse(stream, resp); err != nil {
		return "", fmt.Errorf("write register response: %w", err)
	}

	return backendID, nil
}
