package control

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

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
	if req.Token == "" {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "token is required"})
		return "", &RegistrationError{Message: "token is required"}
	}

	backendID, ok := s.resolveToken(req.Token, req.Backend)
	if !ok {
		WriteResponse(stream, RegisterResponse{OK: false, Error: "invalid token"})
		return "", &RegistrationError{Message: "invalid token"}
	}

	updateAvailable := false
	agentBinPath := findAgentBinary()
	if agentBinPath != "" && req.Version != "" && req.Version != version.Version {
		updateAvailable = true
	}

	resp := RegisterResponse{
		OK:              true,
		Backend:         backendID,
		UpdateAvailable: updateAvailable,
		LatestVersion:   version.Version,
	}

	if err := WriteResponse(stream, resp); err != nil {
		return "", fmt.Errorf("write register response: %w", err)
	}

	if updateAvailable {
		go s.serveAgentUpdate(session, backendID, agentBinPath)
	}

	return backendID, nil
}

func (s *Server) serveAgentUpdate(session *yamux.Session, backendID, binPath string) {
	stream, err := session.AcceptStream()
	if err != nil {
		log.Printf("control: accept update stream for %s: %v", backendID, err)
		return
	}
	defer stream.Close()

	data, err := os.ReadFile(binPath)
	if err != nil {
		log.Printf("control: read agent binary %s: %v", binPath, err)
		return
	}

	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])

	header := UpdateHeader{
		Version: version.Version,
		Size:    int64(len(data)),
		SHA256:  shaHex,
	}
	if err := WriteUpdateHeader(stream, header); err != nil {
		log.Printf("control: write update header to %s: %v", backendID, err)
		return
	}

	if _, err := stream.Write(data); err != nil {
		log.Printf("control: stream agent binary to %s: %v", backendID, err)
		return
	}

	log.Printf("control: successfully pushed auto-update (v%s, %d bytes) to backend %q", version.Version, len(data), backendID)
}

func findAgentBinary() string {
	candidates := []string{
		"/usr/local/bin/sshhub-agent",
		"sshhub-agent",
	}
	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "sshhub-agent"))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}
