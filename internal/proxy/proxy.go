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
	"github.com/Trickhish/sshhub/internal/ratelimit"
	"github.com/Trickhish/sshhub/internal/routing"
	"golang.org/x/crypto/ssh"
)

// Server routes SSH clients to agent-backed backends.
type Server struct {
	cfg       *config.Config
	registry  *control.Registry
	router    *routing.Router
	sshConfig *ssh.ServerConfig
	limiter   *ratelimit.Limiter
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
		limiter:  ratelimit.New(ratelimit.DefaultConfig()),
	}

	sshConfig := &ssh.ServerConfig{
		MaxAuthTries: 6,

		// Public-key only. The hub verifies the client's key WITH THE AGENT
		// (which checks the backend's authorized_keys) and fails closed on any
		// error. The hub asserts no identity of its own and holds no key that
		// authenticates to a backend.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Every rejection below counts as a failure, so enumerating routes or
			// backend names is throttled just like guessing keys.
			res, ok := s.resolveBackend(conn.User())
			if !ok {
				s.limiter.RecordFailure(conn.RemoteAddr())
				return nil, fmt.Errorf("no route for user %q", conn.User())
			}
			backend := s.cfg.BackendByID(res.BackendID)
			if backend == nil {
				s.limiter.RecordFailure(conn.RemoteAddr())
				return nil, fmt.Errorf("backend %q not found", res.BackendID)
			}

			// Delegate authorization to the backend agent in real time. The agent
			// checks the key against end_user's authorized_keys on the node.
			if err := s.verifyBackendAgentKey(backend, res.EndUser, key); err != nil {
				s.limiter.RecordFailure(conn.RemoteAddr())
				return nil, fmt.Errorf("unauthorized key for backend %s", res.BackendID)
			}
			s.limiter.RecordSuccess(conn.RemoteAddr())

			// Record the resolved end user so the session path cannot re-derive a
			// different (client-influenced) value later.
			return &ssh.Permissions{
				Extensions: map[string]string{
					"backend":  res.BackendID,
					"end_user": res.EndUser,
					"pubkey":   string(ssh.MarshalAuthorizedKey(key)),
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
func (s *Server) verifyBackendAgentKey(backend *config.Backend, endUser string, key ssh.PublicKey) error {
	rawConn, err := s.dialBackend(backend)
	if err != nil {
		return err
	}
	defer rawConn.Close()

	// A header exchange, not a full SSH handshake: this runs inside the client's
	// own handshake, so it must stay cheap. (The previous implementation opened
	// a complete SSH connection per key offered, which a client with a large
	// agent could amplify into many backend connections.)
	return control.RequestSession(rawConn, control.SessionRequest{
		Purpose:   control.PurposeVerify,
		EndUser:   endUser,
		ClientKey: string(ssh.MarshalAuthorizedKey(key)),
	})
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

		// Throttle before the handshake: that is the expensive part, and it is
		// reachable by any unauthenticated peer.
		reason, release := s.limiter.Acquire(conn.RemoteAddr())
		if reason != ratelimit.Allowed {
			log.Printf("ssh: refused %s: %s", conn.RemoteAddr(), reason)
			conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer release()
			s.Handle(c)
		}(conn)
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
	// Use the backend and end user pinned during authentication. Re-resolving
	// here would risk diverging from what the agent actually authorized.
	backendID, endUser, err := authorizedTarget(serverConn.Permissions)
	if err != nil {
		log.Printf("ssh: session rejected: %v", err)
		newCh.Reject(ssh.Prohibited, "sshhub: unauthorized")
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
	backendConn, backendChans, backendReqs, err := s.dialBackendAgent(backend, endUser, serverConn.Permissions)
	if err != nil {
		log.Printf("ssh: backend %q auth failed for user %q: %v", backendID, endUser, err)
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

	log.Printf("ssh: session %s -> backend %q (end_user %q)", serverConn.RemoteAddr(), backendID, endUser)

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

	// The authorized backend is the one the agent approved this key for during
	// the handshake. DestAddr is attacker-controlled and MUST NOT widen that
	// grant: previously it was fed back into routing, letting a client
	// authorized for one backend open a raw pipe to another.
	backendID, _, err := authorizedTarget(serverConn.Permissions)
	if err != nil {
		log.Printf("ssh: direct-tcpip rejected: %v", err)
		newCh.Reject(ssh.Prohibited, "sshhub: unauthorized")
		return
	}

	// If the client named a destination, it must resolve to the same backend it
	// was authorized for.
	if requested, ok := s.resolveBackendHint(serverConn.User(), payload.DestAddr); ok {
		if requested.BackendID != backendID {
			log.Printf("ssh: direct-tcpip: client authorized for %q attempted %q (dest %q)",
				backendID, requested.BackendID, payload.DestAddr)
			newCh.Reject(ssh.Prohibited, "sshhub: destination not authorized")
			return
		}
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

// dialBackendAgent opens a session stream to the backend agent, authorized by
// the framed stream header. The hub asserts which end user and which client key;
// the agent independently verifies both. The hub contributes no credential of
// its own, and the client's public key is never used as one.
func (s *Server) dialBackendAgent(backend *config.Backend, endUser string, perms *ssh.Permissions) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	clientKey := ""
	if perms != nil && perms.Extensions != nil {
		clientKey = perms.Extensions["pubkey"]
	}
	if clientKey == "" {
		return nil, nil, nil, fmt.Errorf("no client public key recorded for authorization")
	}

	rawConn, err := s.dialBackend(backend)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := control.RequestSession(rawConn, control.SessionRequest{
		Purpose:   control.PurposeSession,
		EndUser:   endUser,
		ClientKey: clientKey,
	}); err != nil {
		rawConn.Close()
		return nil, nil, nil, err
	}

	hostKeyCallback, err := s.agentHostKeyCallback(backend)
	if err != nil {
		rawConn.Close()
		return nil, nil, nil, err
	}

	// Authorization is complete; this SSH layer only transports the session.
	clientConfig := &ssh.ClientConfig{
		User:            endUser,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: hostKeyCallback,
	}

	return ssh.NewClientConn(rawConn, backend.ID, clientConfig)
}

// agentHostKeyCallback returns the host key policy for dialling a backend
// agent, in order of preference:
//
//  1. host_key / host_key_file from config -- an operator-set pin, strongest.
//  2. the key the agent advertised at registration -- pinned for the lifetime
//     of that control session.
//
// If neither is available the connection is REFUSED. Accepting any key would
// mean a compromised control session could substitute a different endpoint.
func (s *Server) agentHostKeyCallback(backend *config.Backend) (ssh.HostKeyCallback, error) {
	if backend.HostKey != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(backend.HostKey))
		if err != nil {
			return nil, fmt.Errorf("backend %q host_key: %w", backend.ID, err)
		}
		return ssh.FixedHostKey(key), nil
	}

	if backend.HostKeyFile != "" {
		data, err := os.ReadFile(backend.HostKeyFile)
		if err != nil {
			return nil, fmt.Errorf("backend %q host_key_file: %w", backend.ID, err)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("backend %q host_key_file: %w", backend.ID, err)
		}
		return ssh.FixedHostKey(key), nil
	}

	if advertised := s.registry.HostKey(backend.ID); advertised != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(advertised))
		if err != nil {
			return nil, fmt.Errorf("backend %q advertised an unparsable host key: %w", backend.ID, err)
		}
		return ssh.FixedHostKey(key), nil
	}

	return nil, fmt.Errorf("backend %q has no known host key: upgrade the agent so it "+
		"advertises one, or pin it with host_key in the config", backend.ID)
}

// resolution is the outcome of routing a client login to a backend.
type resolution struct {
	// BackendID is the agent-backed backend to relay to.
	BackendID string
	// EndUser is the Unix account the session runs as on that backend. It comes
	// exclusively from the matched route's end_user (or the DefaultEndUser
	// fallback) and is NEVER derived from the client's login string.
	EndUser string
}

// resolveBackend resolves the target backend from the client's login username
// (e.g. "cidev", "root@cidev", "nuc").
func (s *Server) resolveBackend(loginUser string) (resolution, bool) {
	return s.resolveBackendHint(loginUser, "")
}

// resolveBackendHint additionally considers a ProxyJump destination hint.
//
// The login string and hint are ROUTING IDENTIFIERS only. They select which
// route matches; they never determine the Unix account the session runs as.
// That comes from the matched route's end_user, so a client cannot request a
// privileged account by choosing its login name.
func (s *Server) resolveBackendHint(loginUser, hint string) (resolution, bool) {
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

		if r, ok := s.router.ResolveRoute(req); ok {
			return s.fromRoute(r), true
		}
		if r, ok := s.router.ResolveRoute(routing.Request{Username: "*", Hostname: host}); ok {
			return s.fromRoute(r), true
		}
		if b := s.cfg.BackendByID(host); b != nil {
			return s.fromBackendID(b.ID), true
		}
	}

	if req.Hostname != "" {
		if r, ok := s.router.ResolveRoute(req); ok {
			return s.fromRoute(r), true
		}
		if b := s.cfg.BackendByID(req.Hostname); b != nil {
			return s.fromBackendID(b.ID), true
		}
	}

	if b := s.cfg.BackendByID(req.Username); b != nil {
		return s.fromBackendID(b.ID), true
	}
	if r, ok := s.router.ResolveRoute(routing.Request{Username: "*", Hostname: req.Username}); ok {
		return s.fromRoute(r), true
	}
	if r, ok := s.router.ResolveRoute(req); ok {
		return s.fromRoute(r), true
	}

	return resolution{}, false
}

// fromRoute builds a resolution from an explicitly matched route.
func (s *Server) fromRoute(r config.Route) resolution {
	return resolution{BackendID: r.Backend, EndUser: r.ResolvedEndUser()}
}

// fromBackendID builds a resolution for a direct backend-ID match, where no
// route was involved and therefore no end_user was specified.
func (s *Server) fromBackendID(id string) resolution {
	return resolution{BackendID: id, EndUser: config.DefaultEndUser}
}

// authorizedTarget returns the backend and end user that were authorized by the
// agent during the SSH handshake and recorded in Permissions. It fails closed:
// a connection without these extensions never reached a successful
// PublicKeyCallback and must not be served.
func authorizedTarget(perms *ssh.Permissions) (backendID, endUser string, err error) {
	if perms == nil || perms.Extensions == nil {
		return "", "", fmt.Errorf("connection has no authorization record")
	}
	backendID = perms.Extensions["backend"]
	endUser = perms.Extensions["end_user"]
	if backendID == "" || endUser == "" {
		return "", "", fmt.Errorf("connection has incomplete authorization record")
	}
	return backendID, endUser, nil
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
