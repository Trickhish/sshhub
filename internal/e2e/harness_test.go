// Package e2e stands up real sshhub infrastructure and attacks it.
//
// # WHY THIS EXISTS
//
// Unit tests exercise components against in-package fakes, which is exactly the
// setting in which a security regression can pass unnoticed: a fake that speaks
// the old protocol keeps passing after the real one changes. These tests wire
// the REAL hub, the REAL agent, and a REAL control tunnel together and then
// drive them with hostile clients built from raw x/crypto/ssh.
//
// Every attack asserts a NEGATIVE (must not authenticate / must not reach a
// backend / must not run a process). Negative assertions are only meaningful
// alongside a positive control proving the system works at all -- otherwise a
// totally broken build passes every test. TestHarness_AuthorizedUserCanRunCommand
// is that control, and it runs first.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
	"github.com/Trickhish/sshhub/internal/proxy"
	"golang.org/x/crypto/ssh"
)

// harness is a running hub + agent pair connected by a real control tunnel.
type harness struct {
	SSHAddr       string     // hub's client-facing SSH listener
	ControlAddr   string     // hub's control listener
	Token         string     // valid agent registration token
	Pin           string     // hub's TLS public key pin
	Backend       string     // registered backend id
	EndUser       string     // Unix account sessions run as
	AuthorizedKey ssh.Signer // key present in EndUser's authorized_keys
	AgentHostKey  string
}

// testAccount creates a real local Unix account with a home directory and
// authorized_keys, and removes it afterwards.
//
// A real account matters: the privilege-drop and authorized_keys-scoping
// behaviour under test are properties of the OS, not of a mock.
func testAccount(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("must run as root to create the test account")
	}

	name := fmt.Sprintf("sshhube2e%d", time.Now().UnixNano()%100000)
	home := filepath.Join("/home", name)

	out, err := exec.Command("useradd", "-m", "-d", home, "-s", "/bin/sh", name).CombinedOutput()
	if err != nil {
		t.Skipf("cannot create test account (%v): %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("userdel", "-r", name).Run()
	})

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}

	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	// The account must own its own .ssh, as on a real host.
	_ = exec.Command("chown", "-R", u.Uid+":"+u.Gid, sshDir).Run()

	return name
}

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

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s never came up", addr)
}

// newHarness starts a hub and a real agent connected over TLS, with a test
// account whose authorized_keys contains one known-good key.
func newHarness(t *testing.T) *harness {
	t.Helper()

	clientSigner, _ := generateKey(t)
	endUser := testAccount(t, clientSigner.PublicKey())

	dir := t.TempDir()

	// Hub TLS identity.
	cert, err := hubtls.LoadOrCreate(
		filepath.Join(dir, "control-cert.pem"),
		filepath.Join(dir, "control-key.pem"),
		[]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := hubtls.Fingerprint(leaf)

	// Hub SSH host key.
	_, hubHostPEM := generateKey(t)
	hostKeyPath := filepath.Join(dir, "ssh_host_key")
	if err := os.WriteFile(hostKeyPath, []byte(hubHostPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	const backendID = "node1"
	const token = "e2e-valid-token"

	cfg := &config.Config{
		Listen:   config.Listen{SSH: "127.0.0.1:0", Control: "127.0.0.1:0"},
		HostKey:  hostKeyPath,
		Backends: []config.Backend{{ID: backendID, Mode: "reverse", Token: token}},
		Routes: []config.Route{
			{Match: config.Match{Hostname: backendID}, Hostname: backendID, Backend: backendID, EndUser: endUser},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	registry := control.NewRegistry()
	controlSrv := control.NewServer(registry, func(tok, requested string) (string, bool) {
		if tok == token {
			return backendID, true
		}
		return "", false
	}, hubtls.ServerConfig(cert))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	controlAddr := freePort(t)
	go controlSrv.ListenAndServe(ctx, controlAddr)
	waitListening(t, controlAddr)

	// Real agent with a persistent host key.
	agentSrv, err := control.NewAgentServerWithHostKey(filepath.Join(dir, "agent_host_key"))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := hubtls.ClientConfig("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	session, assigned, err := control.ConnectWithHostKey(ctx, controlAddr, backendID, token, agentSrv.HostKey(), tlsCfg)
	if err != nil {
		t.Fatalf("agent could not register: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	go agentSrv.ServeStreams(ctx, session)

	if assigned != backendID {
		t.Fatalf("agent assigned to %q, want %q", assigned, backendID)
	}

	// Hub SSH front end.
	proxySrv, err := proxy.New(cfg, registry)
	if err != nil {
		t.Fatal(err)
	}
	sshAddr := freePort(t)
	go proxySrv.Serve(ctx, sshAddr)
	waitListening(t, sshAddr)

	return &harness{
		SSHAddr:       sshAddr,
		ControlAddr:   controlAddr,
		Token:         token,
		Pin:           pin,
		Backend:       backendID,
		EndUser:       endUser,
		AuthorizedKey: clientSigner,
		AgentHostKey:  agentSrv.HostKey(),
	}
}

// dial opens an SSH connection to the hub with the given auth methods.
func (h *harness) dial(t *testing.T, login string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", h.SSHAddr, &ssh.ClientConfig{
		User:            login,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

// run executes a command through the hub and returns its output.
func (h *harness) run(t *testing.T, login string, auth []ssh.AuthMethod, cmd string) (string, error) {
	t.Helper()
	client, err := h.dial(t, login, auth)
	if err != nil {
		return "", err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	out, err := sess.Output(cmd)
	return string(out), err
}
