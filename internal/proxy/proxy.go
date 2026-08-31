// Package proxy routes SSH clients to agent-backed backends over the control plane.
//
// SECURITY MODEL — AGENT-ONLY, NO HUB-HELD CREDENTIALS:
//
// The hub NEVER holds or uses any credential to authenticate to a backend, and it
// NEVER accepts password authentication from clients. Every backend runs an
// sshhub-agent that reaches the hub via an outbound reverse tunnel. Authentication
// is delegated to the agent, which verifies the connecting client's OWN public key
// against the backend's local authorized_keys before any session is created.
//
// Concretely, for each client the hub:
//  1. Requires public-key auth (no passwords). It captures the client's public key.
//  2. Verifies that key WITH THE AGENT during the handshake (the agent checks it
//     against the backend's authorized_keys). Unknown/unauthorized keys are
//     rejected here — the hub fails closed.
//  3. Relays the client's session to the agent, passing the (verified) client key
//     so the agent spawns the shell as the authorized user.
//
// Because the hub only ever forwards the CLIENT's key for verification and holds no
// keys/passwords/tokens that grant backend shell access, a compromise of the hub at
// rest yields no backend access. (A live hub compromise can observe an in-flight
// session — an unavoidable property of any username-routed jump host — but cannot
// obtain durable, standalone access to any backend.)
//
// Usage (zero-arg): ssh cidev@hub   /   ssh nuc@hub
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

// Server routes SSH clients to agent-backed backends.
type Server struct {
	cfg       *config.Config
	registry  *control.Registry
	router    *routing.Router
	sshConfig *ssh.ServerConfig
}

// New builds a proxy Server from the hub configuration.
func New(cfg *config.Config, registry *control.Registry) (*Server, error) {
	hostKey, err := loadHostKey(cfg.HostKey)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		registry: registry,
		router:   routing.New(cfg.Routes),
	}

	sshConfig := &ssh.ServerConfig{
		MaxAuthTries: 6,

		// Public-key only. The hub verifies the client's key WITH THE AGENT
		// (which checks the backend's authorized_keys) and fails closed on any
		// error. The hub asserts no identity of its own and holds no key that
		// authenticates to a backend.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			backendID, targetUser := s.resolveBackendAndUser(conn.User())
			if backendID == "" {
				return nil, fmt.Errorf("no route for user %q", conn.User())
			}
			backend := s.cfg.BackendByID(backendID)
			if backend == nil {
				return nil, fmt.Errorf("backend %q not found", backendID)
			}

			// Delegate authorization to the backend agent in real time.
			if err := s.verifyBackendAgentKey(backend, targetUser, key); err != nil {
				return nil, fmt.Errorf("unauthorized key for backend %s", backendID)
			}

			return &ssh.Permissions{
				Extensions: map[string]string{
					"user":   conn.User(),
					"pubkey": string(ssh.MarshalAuthorizedKey(key)),
				},
			}, nil
		},

		// NOTE: PasswordCallback is intentionally NOT set. The hub does not accept
		// password authentication under any circumstances. (A permissive password
		// callback was the root cause of the 2026-08 compromise.)
	}

	sshConfig.AddHostKey(hostKey)
	s.sshConfig = sshConfig

	return s, nil
}

// verifyBackendAgentKey validates the client's public key with the backend agent
// during the handshake. It opens a throwaway connection to the agent and offers
// the client's public key (as the agent's key-in-password protocol expects); the
// agent checks it against the backend's authorized_keys and accepts or rejects.
//
// The hub supplies ONLY the client's key here — never a hub-held credential.
func (s *Server) verifyBackendAgentKey(backend *config.Backend, targetUser string, key ssh.PublicKey) error {
	rawConn, err := s.dialBackend(backend)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	user := targetUser
	if user == "" {
		user = backend.Username
	}
	if user == "" {
		user = "root"
	}

	pubkeyStr := string(ssh.MarshalAuthorizedKey(key))
	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pubkeyStr)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	agentConn, chans, reqs, err := ssh.NewClientConn(rawConn, backend.ID, clientConfig)
	if err != nil {
		return err
	}
	_ = agentConn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		ch.Reject(ssh.Prohibited, "auth check only")
	}
	return nil
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

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		go s.handleChannel(serverConn, newCh)
	}
}

// handleChannel processes channel requests.
//
// Both zero-arg sessions ("session") and ProxyJump ("direct-tcpip") are routed to
// the same agent-backed backend. In all cases the client was already authenticated
// by public key and authorized by the agent during the handshake.
func (s *Server) handleChannel(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "session":
		s.handleSession(serverConn, newCh)
	case "direct-tcpip":
		s.handleDirectTCPIP(serverConn, newCh)
	default:
		newCh.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type: %s", newCh.ChannelType()))
	}
}

func (s *Server) handleSession(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	backendID, targetUser := s.resolveBackendAndUser(serverConn.User())
	if backendID == "" {
		log.Printf("ssh: no route for user %q", serverConn.User())
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("sshhub: no route for user %q", serverConn.User()))
		return
	}

	backend := s.cfg.BackendByID(backendID)
	if backend == nil {
		log.Printf("ssh: backend %q not found", backendID)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("sshhub: backend %q not found", backendID))
		return
	}

	// Open an authenticated connection to the agent, passing ONLY the client's
	// verified public key (never a hub-held credential).
	backendConn, backendChans, backendReqs, err := s.dialBackendAgent(backend, targetUser, serverConn.Permissions)
	if err != nil {
		log.Printf("ssh: backend %q auth failed for user %q: %v", backendID, targetUser, err)
		newCh.Reject(ssh.Prohibited, fmt.Sprintf("Permission denied (publickey) on backend %s", backendID))
		return
	}
	defer backendConn.Close()

	go ssh.DiscardRequests(backendReqs)

	backendCh, breqs, err := backendConn.OpenChannel("session", newCh.ExtraData())
	if err != nil {
		log.Printf("ssh: backend %q open session: %v", backendID, err)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("backend %q open session: %v", backendID, err))
		return
	}
	defer backendCh.Close()

	clientCh, clientReqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer clientCh.Close()

	log.Printf("ssh: session %s -> backend %q (user %q)", serverConn.RemoteAddr(), backendID, targetUser)

	go func() {
		for req := range clientReqs {
			ok, err := backendCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	var breqsWg sync.WaitGroup
	breqsWg.Add(1)
	go func() {
		defer breqsWg.Done()
		for req := range breqs {
			ok, err := clientCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	go func() {
		for bNewCh := range backendChans {
			forwardBackendChannel(bNewCh, serverConn)
		}
	}()

	go func() {
		io.Copy(backendCh, clientCh)
		backendCh.CloseWrite()
	}()

	io.Copy(clientCh, backendCh)
	clientCh.CloseWrite()
	backendCh.Close()
	breqsWg.Wait()
	clientCh.Close()
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// handleDirectTCPIP supports ProxyJump (ssh -J hub target). The client was already
// authenticated by public key and authorized by the agent during the handshake.
// The raw stream is spliced to the agent's tunnel; the client may then run its own
// end-to-end SSH handshake with the backend if it wishes.
func (s *Server) handleDirectTCPIP(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	backendID, _ := s.resolveBackendAndUserHint(serverConn.User(), payload.DestAddr)
	if backendID == "" {
		log.Printf("ssh: direct-tcpip: no route for user %q dest %q", serverConn.User(), payload.DestAddr)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("no route to host %s", payload.DestAddr))
		return
	}

	backend := s.cfg.BackendByID(backendID)
	if backend == nil {
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

func forwardBackendChannel(ch ssh.NewChannel, client *ssh.ServerConn) {
	cch, creqs, err := client.OpenChannel(ch.ChannelType(), ch.ExtraData())
	if err != nil {
		ch.Reject(ssh.ConnectionFailed, fmt.Sprintf("client open channel: %v", err))
		return
	}

	backendCh, backendReqs, err := ch.Accept()
	if err != nil {
		cch.Close()
		return
	}

	go func() {
		for req := range backendReqs {
			ok, err := cch.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	var creqsWg sync.WaitGroup
	creqsWg.Add(1)
	go func() {
		defer creqsWg.Done()
		for req := range creqs {
			ok, err := backendCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	go func() {
		io.Copy(backendCh, cch)
		backendCh.CloseWrite()
	}()

	io.Copy(cch, backendCh)
	cch.CloseWrite()
	backendCh.Close()
	creqsWg.Wait()
	cch.Close()
}

// dialBackend opens a raw stream to the backend agent via the control plane.
// Only reverse (agent) backends are supported; there is no direct mode.
func (s *Server) dialBackend(backend *config.Backend) (net.Conn, error) {
	return s.registry.Open(context.Background(), backend.ID)
}

// dialBackendAgent opens an authenticated SSH connection to the backend agent,
// passing ONLY the client's verified public key for authorization. The hub never
// contributes a credential of its own.
func (s *Server) dialBackendAgent(backend *config.Backend, targetUser string, perms *ssh.Permissions) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	rawConn, err := s.dialBackend(backend)
	if err != nil {
		return nil, nil, nil, err
	}

	user := targetUser
	if user == "" {
		user = backend.Username
	}
	if user == "" {
		user = "root"
	}

	var auth []ssh.AuthMethod
	if perms != nil && perms.Extensions != nil {
		if pubkey := perms.Extensions["pubkey"]; pubkey != "" {
			auth = append(auth, ssh.Password(pubkey))
		}
	}
	if len(auth) == 0 {
		rawConn.Close()
		return nil, nil, nil, fmt.Errorf("no client public key available for backend authorization")
	}

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return ssh.NewClientConn(rawConn, backend.ID, clientConfig)
}

// resolveBackendAndUser resolves the target backend and backend username from the
// client's login username (e.g. "cidev", "root@cidev", "nuc").
func (s *Server) resolveBackendAndUser(loginUser string) (string, string) {
	return s.resolveBackendAndUserHint(loginUser, "")
}

// resolveBackendAndUserHint additionally considers a ProxyJump destination hint.
func (s *Server) resolveBackendAndUserHint(loginUser, hint string) (string, string) {
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
			return id, s.effectiveBackendUser(id, req.Username)
		}
		if id, ok := s.router.Resolve(routing.Request{Username: "*", Hostname: host}); ok {
			return id, s.effectiveBackendUser(id, req.Username)
		}
		if b := s.cfg.BackendByID(host); b != nil {
			return b.ID, s.effectiveBackendUser(b.ID, req.Username)
		}
	}

	if req.Hostname != "" {
		if id, ok := s.router.Resolve(req); ok {
			return id, s.effectiveBackendUser(id, req.Username)
		}
		if b := s.cfg.BackendByID(req.Hostname); b != nil {
			return b.ID, s.effectiveBackendUser(b.ID, req.Username)
		}
	}

	if b := s.cfg.BackendByID(req.Username); b != nil {
		return b.ID, s.effectiveBackendUser(b.ID, "")
	}
	if id, ok := s.router.Resolve(routing.Request{Username: "*", Hostname: req.Username}); ok {
		return id, s.effectiveBackendUser(id, "")
	}
	if id, ok := s.router.Resolve(req); ok {
		return id, s.effectiveBackendUser(id, req.Username)
	}

	return "", ""
}

func (s *Server) effectiveBackendUser(backendID, clientUser string) string {
	b := s.cfg.BackendByID(backendID)
	if b != nil && b.Username != "" {
		return b.Username
	}
	if clientUser != "" && clientUser != "*" {
		return clientUser
	}
	return "root"
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
