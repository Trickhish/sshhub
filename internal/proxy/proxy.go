// Package proxy implements transparent Layer-4 SSH passthrough between clients and backends.
//
// Clients connect using standard ProxyJump (-J), ProxyCommand (-W), or ~/.ssh/config.
// SSHub transparently bridges the direct-tcpip channel to the target backend (either via
// direct TCP dial or reverse yamux multiplexed tunnel). The client and backend perform
// end-to-end Diffie-Hellman key exchange and authentication directly.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/routing"
	"golang.org/x/crypto/ssh"
)

// Server routes SSH clients to backends in pure passthrough mode.
type Server struct {
	cfg       *config.Config
	registry  *control.Registry
	router    *routing.Router
	sshConfig *ssh.ServerConfig
}

// New builds a passthrough proxy Server from the hub configuration.
func New(cfg *config.Config, registry *control.Registry) (*Server, error) {
	hostKey, err := loadHostKey(cfg.HostKey)
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	if cfg.AuthorizedKeys != "" {
		keys, err := loadAuthorizedKeys(cfg.AuthorizedKeys)
		if err != nil {
			return nil, err
		}
		sshConfig.NoClientAuth = false
		sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := keys[string(key.Marshal())]; ok {
				return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		}
	}

	sshConfig.AddHostKey(hostKey)

	return &Server{
		cfg:       cfg,
		registry:  registry,
		router:    routing.New(cfg.Routes),
		sshConfig: sshConfig,
	}, nil
}

// Serve accepts SSH client connections until ctx is canceled.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	log.Printf("ssh listener on %s", addr)

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
		go s.Handle(conn)
	}
}

// Handle processes a single inbound client connection.
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("ssh: handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer serverConn.Close()

	// Discard global out-of-band requests.
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		go s.handleChannel(serverConn, newCh)
	}
}

// handleChannel processes incoming channels.
func (s *Server) handleChannel(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "direct-tcpip":
		s.handleDirectTCPIP(serverConn, newCh)
	default:
		newCh.Reject(ssh.Prohibited, "sshhub operates in passthrough mode; please connect using ProxyJump: ssh -J <hub> <user@backend>")
	}
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Server) handleDirectTCPIP(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	backendID := s.resolveBackend(serverConn.User(), payload.DestAddr)
	if backendID == "" {
		log.Printf("ssh: direct-tcpip: no route for user %q dest %q", serverConn.User(), payload.DestAddr)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("no route to host %s", payload.DestAddr))
		return
	}

	backend := s.cfg.BackendByID(backendID)
	if backend == nil {
		log.Printf("ssh: backend %q not found", backendID)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("backend %q not found", backendID))
		return
	}

	backendConn, err := s.dialBackend(backend)
	if err != nil {
		log.Printf("ssh: connect to backend %q: %v", backendID, err)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("connect to backend %q: %v", backendID, err))
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		backendConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	log.Printf("ssh: direct-tcpip %s -> backend %q (dest %s)", serverConn.RemoteAddr(), backendID, payload.DestAddr)
	bridge(ch, backendConn)
}

func (s *Server) resolveBackend(loginUser, hint string) string {
	req := routing.ParseRequest(loginUser)
	hint = strings.TrimSpace(hint)

	if hint != "" {
		host := hint
		if h, _, err := net.SplitHostPort(hint); err == nil {
			host = h
		}

		hintReq := routing.ParseRequest(host)
		if hintReq.Hostname != "" {
			if hintReq.Username != "" {
				req.Username = hintReq.Username
			}
			req.Hostname = hintReq.Hostname
		} else if req.Hostname == "" {
			req.Hostname = host
		}

		if id, ok := s.router.Resolve(req); ok {
			return id
		}

		if id, ok := s.router.Resolve(routing.Request{Username: "*", Hostname: host}); ok {
			return id
		}

		if b := s.cfg.BackendByID(host); b != nil {
			return b.ID
		}
	}

	if req.Hostname != "" {
		if id, ok := s.router.Resolve(req); ok {
			return id
		}
		if b := s.cfg.BackendByID(req.Hostname); b != nil {
			return b.ID
		}
	}

	if b := s.cfg.BackendByID(req.Username); b != nil {
		return b.ID
	}

	if id, ok := s.router.Resolve(req); ok {
		return id
	}

	return ""
}

// dialBackend opens a raw network stream to the backend.
func (s *Server) dialBackend(backend *config.Backend) (net.Conn, error) {
	if backend.Mode == "reverse" {
		return s.registry.Open(context.Background(), backend.ID)
	}
	return net.Dial("tcp", backend.Address)
}

// bridge copies bytes bidirectionally between two streams.
func bridge(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	wg.Wait()
}

func loadHostKey(path string) (ssh.Signer, error) {
	return loadSigner(path)
}

func loadSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	return signer, nil
}

// loadAuthorizedKeys returns the set of authorized public keys, keyed by their
// marshaled form.
func loadAuthorizedKeys(path string) (map[string]struct{}, error) {
	if path == "" {
		return nil, fmt.Errorf("authorized_keys is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized_keys: %w", err)
	}
	keys := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			log.Printf("warning: skipping unparsable authorized_keys line: %v", err)
			continue
		}
		keys[string(key.Marshal())] = struct{}{}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys in authorized_keys")
	}
	return keys, nil
}
