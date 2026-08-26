// Package proxy implements transparent SSH routing between clients and backends.
//
// Clients can connect directly using standard SSH commands (e.g. ssh user@backend@hub
// or ssh backend@hub) for full interactive shells, exec commands, SFTP, and port
// forwarding, or connect via ProxyJump (-J) / direct-tcpip for end-to-end raw stream
// passthrough.
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
	"golang.org/x/crypto/ssh/knownhosts"
)

// Server routes SSH clients to backends.
type Server struct {
	cfg       *config.Config
	registry  *control.Registry
	router    *routing.Router
	signer    ssh.Signer
	sshConfig *ssh.ServerConfig
}

// New builds a proxy Server from the hub configuration.
func New(cfg *config.Config, registry *control.Registry) (*Server, error) {
	hostKey, err := loadHostKey(cfg.HostKey)
	if err != nil {
		return nil, err
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: cfg.AuthorizedKeys == "",
	}

	if cfg.AuthorizedKeys != "" {
		keys, err := loadAuthorizedKeys(cfg.AuthorizedKeys)
		if err != nil {
			return nil, err
		}
		sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := keys[string(key.Marshal())]; ok {
				return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
			}
			return nil, fmt.Errorf("unknown public key")
		}
	} else {
		sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{Extensions: map[string]string{"user": conn.User()}}, nil
		}
	}

	sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		return &ssh.Permissions{
			Extensions: map[string]string{
				"user":     conn.User(),
				"password": string(password),
			},
		}, nil
	}

	sshConfig.AddHostKey(hostKey)

	return &Server{
		cfg:       cfg,
		registry:  registry,
		router:    routing.New(cfg.Routes),
		signer:    hostKey,
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

// handleChannel processes channel requests (direct-tcpip or session).
func (s *Server) handleChannel(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "direct-tcpip":
		s.handleDirectTCPIP(serverConn, newCh)
	case "session":
		s.handleSession(serverConn, newCh)
	default:
		newCh.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type: %s", newCh.ChannelType()))
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

	backendID, _ := s.resolveBackendAndUser(serverConn.User(), payload.DestAddr)
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

func (s *Server) handleSession(serverConn *ssh.ServerConn, newCh ssh.NewChannel) {
	backendID, targetUser := s.resolveBackendAndUser(serverConn.User(), "")
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

	// Dial the backend SSH server
	backendConn, backendChans, backendReqs, err := s.dialBackendSSHConn(backend, targetUser, serverConn.Permissions)
	if err != nil {
		log.Printf("ssh: dial backend %q: %v", backendID, err)
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("backend %q ssh: %v", backendID, err))
		return
	}
	defer backendConn.Close()

	// Discard unhandled backend requests in background
	go ssh.DiscardRequests(backendReqs)

	// Open matching session channel on backend
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

	// Forward client requests to backend (pty-req, shell, exec, window-change, env, subsystem, etc.)
	go func() {
		for req := range clientReqs {
			ok, err := backendCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	// Forward backend requests to client (exit-status, exit-signal, etc.)
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

	// Forward any backend-initiated reverse channels (e.g. agent forwarding)
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

// resolveBackendAndUser extracts the target backend ID and the backend username from
// the client's login username and/or extra hint (such as direct-tcpip DestAddr).
func (s *Server) resolveBackendAndUser(loginUser, hint string) (string, string) {
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

	// If loginUser has an explicit hostname (e.g. "root@cidev" or "alice@web1"):
	if req.Hostname != "" {
		if id, ok := s.router.Resolve(req); ok {
			return id, s.effectiveBackendUser(id, req.Username)
		}
		if b := s.cfg.BackendByID(req.Hostname); b != nil {
			return b.ID, s.effectiveBackendUser(b.ID, req.Username)
		}
	}

	// If loginUser directly matches a backend ID (e.g. "ssh cidev@hub"):
	if b := s.cfg.BackendByID(req.Username); b != nil {
		return b.ID, s.effectiveBackendUser(b.ID, "")
	}

	// Try standard routing rules:
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

// dialBackend opens a raw network stream to the backend.
func (s *Server) dialBackend(backend *config.Backend) (net.Conn, error) {
	if backend.Mode == "reverse" {
		return s.registry.Open(context.Background(), backend.ID)
	}
	return net.Dial("tcp", backend.Address)
}

// dialBackendSSHConn connects to the backend and initiates an SSH client connection.
func (s *Server) dialBackendSSHConn(backend *config.Backend, targetUser string, perms *ssh.Permissions) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	rawConn, err := s.dialBackend(backend)
	if err != nil {
		return nil, nil, nil, err
	}

	clientConfig, err := s.backendClientConfig(backend, targetUser, perms)
	if err != nil {
		rawConn.Close()
		return nil, nil, nil, err
	}

	return ssh.NewClientConn(rawConn, backend.ID, clientConfig)
}

func (s *Server) backendClientConfig(backend *config.Backend, targetUser string, perms *ssh.Permissions) (*ssh.ClientConfig, error) {
	user := targetUser
	if user == "" {
		user = backend.Username
	}
	if user == "" {
		user = "root"
	}

	var authMethods []ssh.AuthMethod

	// 1. Configured backend private key
	if backend.Auth.PrivateKey != "" {
		signer, err := loadSigner(backend.Auth.PrivateKey)
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	// 2. Hub's default signer (hub host key)
	if s.signer != nil {
		authMethods = append(authMethods, ssh.PublicKeys(s.signer))
	}

	// 3. Client's password if provided
	if perms != nil && perms.Extensions != nil && perms.Extensions["password"] != "" {
		authMethods = append(authMethods, ssh.Password(perms.Extensions["password"]))
	}

	// 4. Configured backend password
	if backend.Auth.Password != "" {
		authMethods = append(authMethods, ssh.Password(backend.Auth.Password))
	}

	hostKeyCallback, err := s.hostKeyCallback(backend)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
	}, nil
}

func (s *Server) hostKeyCallback(backend *config.Backend) (ssh.HostKeyCallback, error) {
	switch {
	case backend.HostKey != "":
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(backend.HostKey))
		if err != nil {
			return nil, fmt.Errorf("backend %q host_key: %w", backend.ID, err)
		}
		return ssh.FixedHostKey(key), nil
	case backend.HostKeyFile != "":
		cb, err := knownhosts.New(backend.HostKeyFile)
		if err != nil {
			return nil, fmt.Errorf("backend %q host_key_file: %w", backend.ID, err)
		}
		return cb, nil
	default:
		return ssh.InsecureIgnoreHostKey(), nil
	}
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
