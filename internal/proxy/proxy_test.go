package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"golang.org/x/crypto/ssh"
)

// generateKey returns an SSH signer and its PEM-encoded private key.
func generateKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pem.EncodeToMemory(block))
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startBackend runs a minimal SSH server that accepts allowedKey and echoes
// "hello" on every exec. It returns the listener address and host key signer.
func startBackend(t *testing.T, allowedKey ssh.PublicKey) (string, ssh.Signer) {
	t.Helper()
	hostSigner, _ := generateKey(t)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(m ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleBackendConn(conn, serverConfig)
		}
	}()
	return ln.Addr().String(), hostSigner
}

func handleBackendConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		go handleBackendChannel(newCh)
	}
}

func handleBackendChannel(newCh ssh.NewChannel) {
	if newCh.ChannelType() != "session" {
		newCh.Reject(ssh.UnknownChannelType, "unsupported")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			req.Reply(true, nil)
			ch.Write([]byte("hello"))
			ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{}))
			return
		default:
			req.Reply(false, nil)
		}
	}
}

// runSession dials addr with signer, runs "exec", and returns the output.
func runSession(t *testing.T, addr, user string, signer ssh.Signer) string {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	out, err := session.Output("echo hi")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return string(out)
}

func TestProxyDirect(t *testing.T) {
	clientSigner, _ := generateKey(t)
	_, hubHostPEM := generateKey(t)
	hubBackendSigner, hubBackendPEM := generateKey(t)

	backendAddr, backendHost := startBackend(t, hubBackendSigner.PublicKey())

	dir := t.TempDir()
	authorizedKeys := writeFile(t, dir, "authorized_keys", string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey())))
	hostKey := writeFile(t, dir, "host_key", hubHostPEM)
	backendKey := writeFile(t, dir, "backend_key", hubBackendPEM)

	cfg := &config.Config{
		Listen:         config.Listen{SSH: "127.0.0.1:0", Control: "127.0.0.1:0"},
		HostKey:        hostKey,
		AuthorizedKeys: authorizedKeys,
		Backends: []config.Backend{
			{
				ID:       "web1",
				Mode:     "direct",
				Address:  backendAddr,
				Username: "root",
				Auth:     config.Auth{PrivateKey: backendKey},
				HostKey:  string(ssh.MarshalAuthorizedKey(backendHost.PublicKey())),
			},
		},
		Routes: []config.Route{
			{Match: config.Match{Username: "alice"}, Backend: "web1"},
		},
	}

	server, err := New(cfg, control.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	go server.Serve(ctx, addr)
	time.Sleep(100 * time.Millisecond)

	if out := runSession(t, addr, "alice", clientSigner); out != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}

func TestProxyReverse(t *testing.T) {
	clientSigner, _ := generateKey(t)
	_, hubHostPEM := generateKey(t)
	hubBackendSigner, hubBackendPEM := generateKey(t)

	backendAddr, backendHost := startBackend(t, hubBackendSigner.PublicKey())

	dir := t.TempDir()
	authorizedKeys := writeFile(t, dir, "authorized_keys", string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey())))
	hostKey := writeFile(t, dir, "host_key", hubHostPEM)
	backendKey := writeFile(t, dir, "backend_key", hubBackendPEM)

	registry := control.NewRegistry()

	// Control plane: start hub listener and connect an agent.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	controlServer := control.NewServer(registry, func(token string) bool { return token == "secret" }, nil)
	go controlServer.ListenAndServe(ctx, controlAddr)

	cfg := &config.Config{
		Listen:         config.Listen{SSH: "127.0.0.1:0", Control: controlAddr},
		HostKey:        hostKey,
		AuthorizedKeys: authorizedKeys,
		Backends: []config.Backend{
			{
				ID:       "db1",
				Mode:     "reverse",
				Username: "root",
				Auth:     config.Auth{PrivateKey: backendKey},
				HostKey:  string(ssh.MarshalAuthorizedKey(backendHost.PublicKey())),
			},
		},
		Routes: []config.Route{
			{Match: config.Match{Username: "bob"}, Backend: "db1"},
		},
	}

	server, err := New(cfg, registry)
	if err != nil {
		t.Fatal(err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sshAddr := sshLn.Addr().String()
	sshLn.Close()
	go server.Serve(ctx, sshAddr)

	// Connect the agent and bridge to the backend sshd.
	time.Sleep(100 * time.Millisecond)
	session, err := control.Connect(ctx, controlAddr, "db1", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	go control.Serve(ctx, session, backendAddr)

	// Wait for the registry to record the backend.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := registry.Open(ctx, "db1"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if out := runSession(t, sshAddr, "bob", clientSigner); out != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}
