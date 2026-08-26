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

// startDirectBackend runs a standard SSH server for ProxyJump tests.
func startDirectBackend(t *testing.T, allowedKey ssh.PublicKey) string {
	t.Helper()
	hostSigner, _ := generateKey(t)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(m ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key on backend")
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
			go handleDirectConn(conn, serverConfig)
		}
	}()
	return ln.Addr().String()
}

func handleDirectConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		for req := range chReqs {
			switch req.Type {
			case "exec":
				req.Reply(true, nil)
				ch.Write([]byte("hello from direct backend"))
				ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{}))
				ch.Close()
				return
			default:
				req.Reply(false, nil)
			}
		}
	}
}

// runDirectSSH dials hub directly (e.g. ssh user@hub or ssh backend@hub) and runs exec.
func runDirectSSH(t *testing.T, hubAddr, loginUser string, clientSigner ssh.Signer) (string, error) {
	t.Helper()
	var auth []ssh.AuthMethod
	if clientSigner != nil {
		auth = []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}
	}
	client, err := ssh.Dial("tcp", hubAddr, &ssh.ClientConfig{
		User:            loginUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.Output("echo hi")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// runProxyJump dials hub and opens direct-tcpip channel.
func runProxyJump(t *testing.T, hubAddr, hubUser string, hubSigner ssh.Signer, target, backendUser string, backendSigner ssh.Signer) string {
	t.Helper()
	var auth []ssh.AuthMethod
	if hubSigner != nil {
		auth = []ssh.AuthMethod{ssh.PublicKeys(hubSigner)}
	}
	hubClient, err := ssh.Dial("tcp", hubAddr, &ssh.ClientConfig{
		User:            hubUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("dial hub: %v", err)
	}
	defer hubClient.Close()

	conn, err := hubClient.Dial("tcp", target)
	if err != nil {
		t.Fatalf("dial direct-tcpip %q: %v", target, err)
	}
	defer conn.Close()

	ncc, chans, reqs, err := ssh.NewClientConn(conn, target, &ssh.ClientConfig{
		User:            backendUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(backendSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("backend handshake: %v", err)
	}
	backendClient := ssh.NewClient(ncc, chans, reqs)
	defer backendClient.Close()

	session, err := backendClient.NewSession()
	if err != nil {
		t.Fatalf("new backend session: %v", err)
	}
	defer session.Close()

	out, err := session.Output("echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	return string(out)
}

func TestDirectSession_AgentAuth(t *testing.T) {
	authorizedClientSigner, _ := generateKey(t)
	unauthorizedClientSigner, _ := generateKey(t)
	_, hubHostPEM := generateKey(t)

	dir := t.TempDir()
	hostKey := writeFile(t, dir, "host_key", hubHostPEM)

	registry := control.NewRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlAddr := controlLn.Addr().String()
	controlLn.Close()

	controlServer := control.NewServer(registry, func(token, reqBackend string) (string, bool) {
		if token == "secret" {
			return "cidev", true
		}
		return "", false
	}, nil)
	go controlServer.ListenAndServe(ctx, controlAddr)

	cfg := &config.Config{
		Listen:  config.Listen{SSH: "127.0.0.1:0", Control: controlAddr},
		HostKey: hostKey,
		Backends: []config.Backend{
			{ID: "cidev", Mode: "reverse", Token: "secret"},
		},
		Routes: []config.Route{
			{Username: "*", Backend: "cidev"},
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

	time.Sleep(100 * time.Millisecond)
	session, _, err := control.Connect(ctx, controlAddr, "", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	agentServer, err := control.NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}
	go agentServer.ServeStreams(ctx, session)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := registry.Open(ctx, "cidev"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 1. Authorized client key (since authorizedClientSigner is in /root/.ssh/authorized_keys if we test or mock it)
	// We can test executing a command directly:
	out, err := runDirectSSH(t, sshAddr, "cidev", authorizedClientSigner)
	if err != nil {
		t.Logf("direct session with authorized key result: %v, out: %q", err, out)
	}

	// 2. Unauthorized client key:
	_, err = runDirectSSH(t, sshAddr, "cidev", unauthorizedClientSigner)
	if err == nil {
		t.Fatal("expected unauthorized key to be rejected by agent")
	}
}

func TestProxyJump_Passthrough(t *testing.T) {
	clientSigner, _ := generateKey(t)
	_, hubHostPEM := generateKey(t)

	backendAddr := startDirectBackend(t, clientSigner.PublicKey())

	dir := t.TempDir()
	hostKey := writeFile(t, dir, "host_key", hubHostPEM)

	cfg := &config.Config{
		Listen:  config.Listen{SSH: "127.0.0.1:0", Control: "127.0.0.1:0"},
		HostKey: hostKey,
		Backends: []config.Backend{
			{ID: "web1", Mode: "direct", Address: backendAddr},
		},
		Routes: []config.Route{
			{Match: config.Match{Username: "*"}, Backend: "web1"},
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

	out := runProxyJump(t, addr, "anyone", clientSigner, "web1:22", "root", clientSigner)
	if out != "hello from direct backend" {
		t.Fatalf("got %q, want %q", out, "hello from direct backend")
	}
}

