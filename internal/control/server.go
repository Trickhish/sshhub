package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/hashicorp/yamux"
)

// Server is the hub side of the control plane.
type Server struct {
	registry   *Registry
	checkToken func(token string) bool
	tlsConfig  *tls.Config
}

// NewServer builds a Server. checkToken reports whether a presented token is
// authorized. tlsConfig may be nil for a plaintext listener.
func NewServer(registry *Registry, checkToken func(string) bool, tlsConfig *tls.Config) *Server {
	return &Server{
		registry:   registry,
		checkToken: checkToken,
		tlsConfig:  tlsConfig,
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

	s.registry.register(backend, session)
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
	if req.Backend == "" {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "backend id is required"})
		return "", &RegistrationError{Message: "backend id is required"}
	}
	if !s.checkToken(req.Token) {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "invalid token"})
		return "", &RegistrationError{Message: "invalid token"}
	}

	if err := WriteResponse(stream, RegisterResponse{OK: true}); err != nil {
		return "", fmt.Errorf("write register response: %w", err)
	}
	return req.Backend, nil
}
