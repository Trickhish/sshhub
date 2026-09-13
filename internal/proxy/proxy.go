// Package proxy provides an authenticated, forwarding-only SSH jump endpoint.
// Backend authentication and host-key verification belong to the inner SSH
// connection between the user's client and OpenSSH, never to the hub.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/ratelimit"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	cfg       *config.Config
	registry  *control.Registry
	sshConfig *ssh.ServerConfig
	limiter   *ratelimit.Limiter
}

func New(cfg *config.Config, registry *control.Registry) (*Server, error) {
	data, err := os.ReadFile(cfg.HostKey)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, registry: registry, limiter: ratelimit.New(ratelimit.DefaultConfig())}
	s.sshConfig = &ssh.ServerConfig{MaxAuthTries: 24, PublicKeyCallback: s.authorize}
	s.sshConfig.AddHostKey(key)
	return s, nil
}

// Jump keys grant transport access only. Never consult backend authorized_keys
// or send a client identity assertion through the tunnel.
func (s *Server) authorize(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	for _, access := range s.cfg.JumpUsers {
		if access.Name != conn.User() {
			continue
		}
		for _, text := range access.Keys {
			allowed, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
			if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
				continue
			}
			if string(allowed.Marshal()) == string(key.Marshal()) {
				return &ssh.Permissions{Extensions: map[string]string{"jump_user": access.Name}}, nil
			}
		}
	}
	return nil, fmt.Errorf("jump access denied")
}

func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	slots := make(chan struct{}, 256)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		reason, release := s.limiter.Acquire(conn.RemoteAddr())
		if reason != ratelimit.Allowed {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				s.handle(conn, release)
			}()
		default:
			release()
			conn.Close()
		}
	}
}

func (s *Server) Handle(conn net.Conn) { s.handle(conn, func() {}) }

func (s *Server) handle(conn net.Conn, release func()) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	c, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	release()
	if err != nil {
		s.limiter.RecordFailure(conn.RemoteAddr())
		return
	}
	defer c.Close()
	conn.SetDeadline(time.Time{})
	s.limiter.RecordSuccess(conn.RemoteAddr())
	go ssh.DiscardRequests(reqs)
	slots := make(chan struct{}, 16)
	for ch := range chans {
		if ch.ChannelType() != "direct-tcpip" {
			ch.Reject(ssh.Prohibited, "ProxyJump only; direct sessions are disabled")
			continue
		}
		select {
		case slots <- struct{}{}:
			go func(ch ssh.NewChannel) { defer func() { <-slots }(); s.forward(c, ch) }(ch)
		default:
			ch.Reject(ssh.ResourceShortage, "channel limit")
		}
	}
}

type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Server) forward(client *ssh.ServerConn, ch ssh.NewChannel) {
	var p directTCPIPPayload
	if ssh.Unmarshal(ch.ExtraData(), &p) != nil || p.DestPort != 22 {
		ch.Reject(ssh.Prohibited, "only configured backend names on logical port 22 are allowed")
		return
	}
	// Exact backend names only. No DNS resolution, route fallbacks, user-selected
	// network addresses, or hub-selected Unix accounts.
	allowed := false
	for _, u := range s.cfg.JumpUsers {
		if u.Name != client.User() {
			continue
		}
		for _, id := range u.Backends {
			if id == p.DestAddr {
				allowed = true
			}
		}
	}
	if !allowed || s.cfg.BackendByID(p.DestAddr) == nil {
		ch.Reject(ssh.Prohibited, "destination denied")
		return
	}
	backend, err := s.registry.Open(context.Background(), p.DestAddr)
	if err != nil {
		ch.Reject(ssh.ConnectionFailed, "backend unavailable")
		return
	}
	defer backend.Close()
	c, reqs, err := ch.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	go ssh.DiscardRequests(reqs)
	log.Printf("jump user %q -> backend %q", client.User(), p.DestAddr)
	bridge(c, backend)
}

func bridge(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	copyHalf := func(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	<-done
	// Bound peers that never finish the opposite half after EOF.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
