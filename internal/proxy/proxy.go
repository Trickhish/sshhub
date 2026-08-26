// Package proxy implements the SSH hop between a client and a backend.
//
// The hub terminates the client's SSH connection (authenticating the client
// against an authorized_keys file), inspects the requested username and
// hostname, routes to a backend, dials the backend (directly or over a
// reverse control stream), and bridges the SSH channels end to end.
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

// Server routes authenticated SSH clients to backends.
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

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
	}

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

	serverConn, clientChans, clientReqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("ssh: handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer serverConn.Close()

	req := routing.ParseRequest(serverConn.User())
	backendID, ok := s.router.Resolve(req)
	if !ok {
		log.Printf("ssh: no route for user %q host %q", req.Username, req.Hostname)
		return
	}

	backend := s.cfg.BackendByID(backendID)
	if backend == nil {
		log.Printf("ssh: backend %q not found", backendID)
		return
	}

	backendConn, backendChans, backendReqs, err := s.dialBackend(backend, req.Username)
	if err != nil {
		log.Printf("ssh: connect to backend %q: %v", backendID, err)
		return
	}
	defer backendConn.Close()

	log.Printf("ssh: %s -> backend %q (user %q)", conn.RemoteAddr(), backendID, req.Username)
	pipe(serverConn, clientChans, clientReqs, backendConn, backendChans, backendReqs)
}

// dialBackend establishes an SSH client connection to a backend.
func (s *Server) dialBackend(backend *config.Backend, clientUser string) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	clientConfig, err := s.backendClientConfig(backend, clientUser)
	if err != nil {
		return nil, nil, nil, err
	}

	if backend.Mode == "reverse" {
		stream, err := s.registry.Open(context.Background(), backend.ID)
		if err != nil {
			return nil, nil, nil, err
		}
		return ssh.NewClientConn(stream, backend.ID, clientConfig)
	}

	addr := backend.Address
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	return ssh.NewClientConn(c, addr, clientConfig)
}

// backendClientConfig builds the SSH client config used to reach a backend.
func (s *Server) backendClientConfig(backend *config.Backend, clientUser string) (*ssh.ClientConfig, error) {
	user := backend.Username
	if user == "" {
		user = clientUser
	}

	var auth ssh.AuthMethod
	switch {
	case backend.Auth.PrivateKey != "":
		signer, err := loadSigner(backend.Auth.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("backend %q private key: %w", backend.ID, err)
		}
		auth = ssh.PublicKeys(signer)
	case backend.Auth.Password != "":
		auth = ssh.Password(backend.Auth.Password)
	default:
		return nil, fmt.Errorf("backend %q has no auth method configured", backend.ID)
	}

	hostKeyCallback, err := s.hostKeyCallback(backend)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
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
		log.Printf("warning: backend %q has no pinned host key; using insecure host key callback", backend.ID)
		return ssh.InsecureIgnoreHostKey(), nil
	}
}

// pipe forwards channels and requests between the client and backend.
func pipe(client *ssh.ServerConn, clientChans <-chan ssh.NewChannel, clientReqs <-chan *ssh.Request, backend ssh.Conn, backendChans <-chan ssh.NewChannel, backendReqs <-chan *ssh.Request) {
	var wg sync.WaitGroup

	// Forward client-initiated channels to the backend.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newCh := range clientChans {
			go forwardChannel(newCh, backend)
		}
	}()

	// Forward backend-initiated channels to the client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newCh := range backendChans {
			go forwardBackendChannel(newCh, client)
		}
	}()

	// Reject unhandled client global requests.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range clientReqs {
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	// Reject unhandled backend global requests.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range backendReqs {
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	wg.Wait()
}

// forwardChannel opens a matching channel on the backend and bridges it.
func forwardChannel(ch ssh.NewChannel, backend ssh.Conn) {
	bch, breqs, err := backend.OpenChannel(ch.ChannelType(), ch.ExtraData())
	if err != nil {
		ch.Reject(ssh.ConnectionFailed, fmt.Sprintf("backend open channel: %v", err))
		return
	}

	clientCh, clientReqs, err := ch.Accept()
	if err != nil {
		bch.Close()
		return
	}

	// Requests client -> backend.
	go func() {
		for req := range clientReqs {
			ok, err := bch.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	// Requests backend -> client.
	go func() {
		for req := range breqs {
			ok, err := clientCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(bch, clientCh)
		bch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientCh, bch)
		clientCh.CloseWrite()
	}()
	wg.Wait()

	clientCh.Close()
	bch.Close()
}

// forwardBackendChannel opens a matching channel on the client and bridges it.
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

	// Requests backend -> client.
	go func() {
		for req := range backendReqs {
			ok, err := cch.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	// Requests client -> backend.
	go func() {
		for req := range creqs {
			ok, err := backendCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(err == nil && ok, nil)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(cch, backendCh)
		cch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(backendCh, cch)
		backendCh.CloseWrite()
	}()
	wg.Wait()

	cch.Close()
	backendCh.Close()
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
