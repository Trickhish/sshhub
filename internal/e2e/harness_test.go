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
		JumpUsers: []config.JumpUser{{Name: backendID, Keys: []string{string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))}, Backends: []string{backendID}}},
		Listen:    config.Listen{SSH: "127.0.0.1:0", Control: "127.0.0.1:0"},
		HostKey:   hostKeyPath,
		Backends:  []config.Backend{{ID: backendID, Mode: "reverse", Token: token}},
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

	tlsCfg, err := hubtls.ClientConfig("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	session, assigned, err := control.Connect(ctx, controlAddr, backendID, token, tlsCfg)
	if err != nil {
		t.Fatalf("agent could not register: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	backendAddr, backendHostKey := startOpenSSH(t, dir, endUser)
	go control.Serve(ctx, session, backendAddr)

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
		AgentHostKey:  backendHostKey,
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
	if login != h.Backend {
		return "", fmt.Errorf("unknown jump identity")
	}
	client, err := h.dialInner(t, auth)
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

func startOpenSSH(t *testing.T, dir, account string) (string, string) {
	t.Helper()
	signer, pemKey := generateKey(t)
	keyPath := filepath.Join(dir, "backend_key")
	if err := os.WriteFile(keyPath, []byte(pemKey), 0600); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	_, port, _ := net.SplitHostPort(addr)
	path := filepath.Join(dir, "sshd_config")
	text := fmt.Sprintf("ListenAddress 127.0.0.1\nPort %s\nHostKey %s\nPidFile %s\nAuthorizedKeysFile .ssh/authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes yes\nMaxAuthTries 24\nSubsystem sftp internal-sftp\nSetEnv LANG=C.UTF-8 LC_CTYPE=C.UTF-8\n", port, keyPath, filepath.Join(dir, "sshd.pid"))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("usermod", "-p", "*", account).CombinedOutput(); err != nil {
		t.Fatalf("test account: %v %s", err, out)
	}
	cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", path)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitListening(t, addr)
	return addr, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func (h *harness) dialInner(t *testing.T, auth []ssh.AuthMethod) (*ssh.Client, error) {
	outer, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { outer.Close() })
	raw, err := outer.Dial("tcp", h.Backend+":22")
	if err != nil {
		outer.Close()
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.AgentHostKey))
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(raw, h.Backend, &ssh.ClientConfig{User: h.EndUser, Auth: auth, HostKeyCallback: ssh.FixedHostKey(key)})
	if err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}
