package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
)

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

// stubAgent emulates sshhub-agent's authorization contract: the hub sends a
// framed authorization header (see control/streamauth.go) naming the end user
// and the client's public key, and the agent verifies it against an allowlist
// before any SSH machinery runs.
//
// It deliberately reuses the REAL control.AcceptSession/ReplySession helpers, so
// a change to the wire protocol breaks this test rather than silently passing
// against a stale fake.
type stubAgent struct {
	cfg     *ssh.ServerConfig
	allowed string
	hostKey string
	// lastEndUser records the end user the hub asserted, so tests can check
	// that the Unix account came from the route and not from client input.
	mu          sync.Mutex
	lastEndUser string
}

func newStubAgent(t *testing.T, allowed ssh.PublicKey) *stubAgent {
	t.Helper()
	hostSigner, _ := generateKey(t)

	// No client auth: authorization happened in the stream header.
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	return &stubAgent{
		cfg:     cfg,
		allowed: string(allowed.Marshal()),
		hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))),
	}
}

func (a *stubAgent) EndUser() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastEndUser
}

func (a *stubAgent) serveStreams(ctx context.Context, session *yamux.Session) {
	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}
		go a.serve(stream)
	}
}

func (a *stubAgent) serve(conn net.Conn) {
	// Authorize from the framed header before anything else.
	req, err := control.AcceptSession(conn)
	if err != nil {
		conn.Close()
		return
	}

	key, _, _, _, kerr := ssh.ParseAuthorizedKey([]byte(req.ClientKey))
	if kerr != nil || string(key.Marshal()) != a.allowed {
		_ = control.ReplySession(conn, false, "unauthorized")
		conn.Close()
		return
	}
	if err := control.ReplySession(conn, true, ""); err != nil {
		conn.Close()
		return
	}

	a.mu.Lock()
	a.lastEndUser = req.EndUser
	a.mu.Unlock()

	// A verify probe ends here; the hub closes the stream.
	if req.Purpose == control.PurposeVerify {
		conn.Close()
		return
	}

	sConn, chans, reqs, err := ssh.NewServerConn(conn, a.cfg)
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
		go func() {
			for req := range chReqs {
				if req.Type == "exec" {
					req.Reply(true, nil)
					ch.Write([]byte("hello from agent backend"))
					ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{}))
					ch.Close()
					return
				}
				req.Reply(false, nil)
			}
		}()
	}
}

// testHub starts a full hub (control plane + ssh listener) and connects a stub agent
// as backend "cidev" via the real control-plane handshake. Returns the hub ssh addr.
func testHub(t *testing.T, allowed ssh.PublicKey, routes []config.Route) string {
	t.Helper()

	registry := control.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Control server.
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
	time.Sleep(50 * time.Millisecond)

	// Stub agent connects to the control plane as backend "cidev", advertising
	// its host key so the hub can pin it.
	agent := newStubAgent(t, allowed)
	session, _, err := control.ConnectWithHostKey(ctx, controlAddr, "cidev", "secret", agent.hostKey, nil)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	go agent.serveStreams(ctx, session)

	// Hub SSH front end.
	_, hubHostPEM := generateKey(t)
	dir := t.TempDir()
	hostKey := writeFile(t, dir, "host_key", hubHostPEM)

	cfg := &config.Config{
		Listen:   config.Listen{SSH: "127.0.0.1:0", Control: controlAddr},
		HostKey:  hostKey,
		Backends: []config.Backend{{ID: "cidev", Mode: "reverse", Token: "secret"}},
		Routes:   routes,
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

	// Wait for the backend to be registered.
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
	time.Sleep(50 * time.Millisecond)
	return sshAddr
}

func dialHubExec(hubAddr, loginUser string, auth []ssh.AuthMethod) (string, error) {
	client, err := ssh.Dial("tcp", hubAddr, &ssh.ClientConfig{
		User:            loginUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
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
	return string(out), err
}

func catchAll() []config.Route { return []config.Route{{Username: "*", Backend: "cidev"}} }

// A client whose key is authorized on the backend gets a working session (zero-arg).
func TestAuthorizedKey_Succeeds(t *testing.T) {
	clientSigner, _ := generateKey(t)
	hubAddr := testHub(t, clientSigner.PublicKey(), catchAll())

	out, err := dialHubExec(hubAddr, "cidev", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("authorized client should succeed, got: %v", err)
	}
	if out != "hello from agent backend" {
		t.Fatalf("got %q, want %q", out, "hello from agent backend")
	}
}

// A client whose key is NOT authorized on the backend is rejected at the hub (fail closed).
func TestUnauthorizedKey_Rejected(t *testing.T) {
	authorized, _ := generateKey(t)
	attacker, _ := generateKey(t)
	hubAddr := testHub(t, authorized.PublicKey(), catchAll())

	if _, err := dialHubExec(hubAddr, "cidev", []ssh.AuthMethod{ssh.PublicKeys(attacker)}); err == nil {
		t.Fatal("unauthorized key MUST be rejected by the hub")
	}
}

// The hub MUST NOT accept password authentication (root cause of the 2026-08 compromise).
func TestPasswordAuth_Rejected(t *testing.T) {
	authorized, _ := generateKey(t)
	hubAddr := testHub(t, authorized.PublicKey(), catchAll())

	for _, pw := range []string{"", "anything", "root", "hunter2"} {
		if _, err := dialHubExec(hubAddr, "cidev", []ssh.AuthMethod{ssh.Password(pw)}); err == nil {
			t.Fatalf("password auth (%q) MUST be rejected by the hub", pw)
		}
	}
}

// A login matching no route is rejected.
func TestNoRoute_Rejected(t *testing.T) {
	clientSigner, _ := generateKey(t)
	hubAddr := testHub(t, clientSigner.PublicKey(), []config.Route{{Match: config.Match{Hostname: "cidev"}, Backend: "cidev"}})

	if _, err := dialHubExec(hubAddr, "does-not-exist", []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}); err == nil {
		t.Fatal("login with no matching route MUST be rejected")
	}
}

// Config validation must refuse "direct" backends.
func TestDirectMode_Rejected(t *testing.T) {
	cfg := &config.Config{
		Listen:   config.Listen{SSH: "127.0.0.1:0", Control: "127.0.0.1:0"},
		HostKey:  "/dev/null",
		Backends: []config.Backend{{ID: "x", Mode: "direct"}},
		Routes:   []config.Route{{Username: "*", Backend: "x"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("config.Validate MUST reject direct-mode backends")
	}
}
