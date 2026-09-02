package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Trickhish/sshhub/internal/control"
	"github.com/Trickhish/sshhub/internal/hubtls"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Authentication bypass
// ---------------------------------------------------------------------------

// THE ORIGINAL BREACH. A permissive PasswordCallback accepted any password,
// including an empty one, granting a root shell to anyone on the internet.
func TestAttack_EmptyPassword(t *testing.T) {
	h := newHarness(t)

	for _, login := range []string{h.Backend, "root", "root@" + h.Backend, h.EndUser} {
		if _, err := h.dial(t, login, []ssh.AuthMethod{ssh.Password("")}); err == nil {
			t.Fatalf("SECURITY: empty password authenticated as %q", login)
		}
	}
}

func TestAttack_ArbitraryPasswords(t *testing.T) {
	h := newHarness(t)

	for _, pw := range []string{"", " ", "root", "admin", "password", "toor", strings.Repeat("A", 4096)} {
		if _, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.Password(pw)}); err == nil {
			t.Fatalf("SECURITY: password %q authenticated", pw)
		}
	}
}

// Keyboard-interactive is a separate method; refusing passwords is not enough
// if it is left open.
func TestAttack_KeyboardInteractive(t *testing.T) {
	h := newHarness(t)

	answer := func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		ans := make([]string, len(questions))
		for i := range ans {
			ans[i] = ""
		}
		return ans, nil
	}
	if _, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.KeyboardInteractive(answer)}); err == nil {
		t.Fatal("SECURITY: keyboard-interactive authenticated with empty answers")
	}
}

// The "none" method must not succeed.
func TestAttack_NoneAuth(t *testing.T) {
	h := newHarness(t)

	if _, err := h.dial(t, h.Backend, nil); err == nil {
		t.Fatal("SECURITY: authenticated with no credentials at all")
	}
}

// An attacker-generated key, not present in any authorized_keys.
func TestAttack_UnknownPublicKey(t *testing.T) {
	h := newHarness(t)
	attacker, _ := generateKey(t)

	for _, login := range []string{h.Backend, "root@" + h.Backend, h.EndUser + "@" + h.Backend} {
		if _, err := h.dial(t, login, []ssh.AuthMethod{ssh.PublicKeys(attacker)}); err == nil {
			t.Fatalf("SECURITY: unknown public key authenticated as %q", login)
		}
	}
}

// ---------------------------------------------------------------------------
// Bearer-token replay (the pubkey-as-password flaw)
// ---------------------------------------------------------------------------

// A public key is not secret. An attacker who knows a victim's PUBLIC key must
// not be able to use it as a credential -- neither at the hub, nor by speaking
// directly to the agent.
func TestAttack_VictimPublicKeyAsCredential(t *testing.T) {
	h := newHarness(t)

	// The victim's public key, exactly as it appears in authorized_keys.
	victimPub := string(ssh.MarshalAuthorizedKey(h.AuthorizedKey.PublicKey()))

	// (a) As a password to the hub.
	if _, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.Password(victimPub)}); err == nil {
		t.Fatal("SECURITY: victim's public key accepted as a password by the hub")
	}

	// (b) Offering the victim's public key without its private half. The SSH
	// protocol requires a signature, so this must fail; asserting it explicitly
	// guards against a callback that authorizes on the key alone.
	pub, err := ssh.ParsePublicKey(h.AuthorizedKey.PublicKey().Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.dial(t, h.Backend, []ssh.AuthMethod{
		ssh.PublicKeys(&pubKeyOnlySigner{pub: pub}),
	}); err == nil {
		t.Fatal("SECURITY: authenticated with a public key and no private key")
	}
}

// pubKeyOnlySigner has a public key but cannot produce valid signatures,
// modelling an attacker who scraped a key from GitHub or ssh-keyscan.
type pubKeyOnlySigner struct{ pub ssh.PublicKey }

func (s *pubKeyOnlySigner) PublicKey() ssh.PublicKey { return s.pub }
func (s *pubKeyOnlySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	// Return a well-formed but invalid signature.
	return &ssh.Signature{Format: s.pub.Type(), Blob: make([]byte, 64)}, nil
}

// ---------------------------------------------------------------------------
// Control plane
// ---------------------------------------------------------------------------

// An attacker who can reach the control port must not be able to register with
// a guessed token.
func TestAttack_ControlPlaneInvalidToken(t *testing.T) {
	h := newHarness(t)

	tlsCfg, err := hubtls.ClientConfig("127.0.0.1", h.Pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"", "guess", "e2e-valid-token-x", strings.ToUpper(h.Token)} {
		ctx, cancel := shortCtx()
		_, _, err := control.Connect(ctx, h.ControlAddr, h.Backend, tok, tlsCfg)
		cancel()
		if err == nil {
			t.Fatalf("SECURITY: registered with invalid token %q", tok)
		}
	}
}

// The control plane must not be reachable in plaintext: an agent's token would
// be exposed to anyone on-path.
//
// Deliberately does NOT use newHarness: the harness's own agent connects over
// TLS, so if TLS were removed the harness would fail during setup and this test
// would "fail" without ever evaluating its assertion. Standing up a bare control
// listener keeps the assertion itself meaningful.
func TestAttack_ControlPlanePlaintext(t *testing.T) {
	dir := t.TempDir()
	cert, err := hubtls.LoadOrCreate(
		filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	registry := control.NewRegistry()
	srv := control.NewServer(registry, func(tok, req string) (string, bool) {
		return "node1", tok == "valid"
	}, hubtls.ServerConfig(cert))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freePort(t)
	go srv.ListenAndServe(ctx, addr)
	waitListening(t, addr)

	// nil TLS config == plaintext TCP, which is what a pre-0.4.0 agent does.
	dctx, dcancel := shortCtx()
	defer dcancel()
	if _, _, err := control.Connect(dctx, addr, "node1", "valid", nil); err == nil {
		t.Fatal("SECURITY: control plane accepted a plaintext connection; tokens are exposed on the wire")
	}
}

// A second agent presenting a VALID token must not displace the connected one,
// which would let an attacker who stole a token hijack the backend.
func TestAttack_BackendTakeoverWithStolenToken(t *testing.T) {
	h := newHarness(t)

	tlsCfg, err := hubtls.ClientConfig("127.0.0.1", h.Pin)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := shortCtx()
	defer cancel()

	evil, _ := generateKey(t)
	evilHostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(evil.PublicKey())))
	session, _, err := control.ConnectWithHostKey(ctx, h.ControlAddr, h.Backend, h.Token, evilHostKey, tlsCfg)
	if err == nil {
		defer session.Close()
	}

	// Whether or not the duplicate registration is refused outright, the
	// legitimate user must still reach the REAL agent afterwards.
	out, runErr := h.run(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, "id -un")
	if runErr != nil {
		t.Fatalf("SECURITY: a duplicate registration disrupted the legitimate backend: %v", runErr)
	}
	if strings.TrimSpace(out) != h.EndUser {
		t.Fatalf("SECURITY: session was served by an impostor agent (ran as %q)", strings.TrimSpace(out))
	}
}

// ---------------------------------------------------------------------------
// Routing / authorization boundaries
// ---------------------------------------------------------------------------

// Enumerating backend and route names must not authenticate.
func TestAttack_RouteEnumeration(t *testing.T) {
	h := newHarness(t)
	attacker, _ := generateKey(t)

	for _, login := range []string{
		"nonexistent", "root", "admin", "../root", "node1x", "*",
		"root@nonexistent", h.Backend + "@" + h.Backend,
	} {
		if _, err := h.dial(t, login, []ssh.AuthMethod{ssh.PublicKeys(attacker)}); err == nil {
			t.Fatalf("SECURITY: login %q authenticated", login)
		}
	}
}

// A client cannot select a privileged Unix account by choosing its login name;
// the account comes from the route's end_user.
//
// This asserts on the RESOLVED account rather than on whether the connection was
// refused. A refusal-based assertion passes vacuously: with this key absent from
// root's authorized_keys the attempt fails anyway, so the test would still pass
// even if the login string were feeding account selection. Here the client key
// IS authorized for root, so the only thing preventing a root session is that
// end_user comes from config.
func TestAttack_CannotChooseUnixAccountViaLogin(t *testing.T) {
	h := newHarness(t)

	// Authorize this exact key for root as well, removing authorization as the
	// reason the attack fails.
	rootAK := "/root/.ssh/authorized_keys"
	orig := readFileOrEmpty(t, rootAK)
	t.Cleanup(func() { restoreFile(t, rootAK, orig) })
	appendAuthorizedKey(t, rootAK, h.AuthorizedKey.PublicKey())

	for _, login := range []string{"root@" + h.Backend, "root", "0@" + h.Backend} {
		out, err := h.run(t, login, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, "id -un")
		if err != nil {
			t.Logf("login %q refused: %v", login, err)
			continue
		}
		got := strings.TrimSpace(out)
		if got == "root" {
			t.Fatalf("SECURITY: login %q produced a ROOT session; the client selected its own Unix account", login)
		}
		if got != h.EndUser {
			t.Fatalf("login %q ran as %q, expected the route's end_user %q", login, got, h.EndUser)
		}
		t.Logf("login %q correctly ran as %q", login, got)
	}
}

// ---------------------------------------------------------------------------
// Brute force / resource exhaustion
// ---------------------------------------------------------------------------

// Sustained guessing must be throttled rather than allowed to run unbounded.
func TestAttack_BruteForceIsThrottled(t *testing.T) {
	h := newHarness(t)

	var refusedAtTransport int
	deadline := time.Now().Add(30 * time.Second)

	for i := 0; i < 60 && time.Now().Before(deadline); i++ {
		attacker, _ := generateKey(t)
		c, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(attacker)})
		if err == nil {
			c.Close()
			t.Fatal("SECURITY: brute-force attempt authenticated")
		}
		// Once blocked, the hub closes the connection before the SSH banner, so
		// the failure mode changes from an auth error to a transport error.
		if isTransportRefusal(err) {
			refusedAtTransport++
		}
	}

	if refusedAtTransport == 0 {
		t.Error("no connection was refused before the handshake: brute-force throttling does not appear to engage")
	} else {
		t.Logf("throttling engaged: %d/60 attempts refused before the handshake", refusedAtTransport)
	}
}

// isTransportRefusal reports whether the connection was dropped before SSH
// authentication, which is how the rate limiter refuses.
func isTransportRefusal(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "closed") ||
		strings.Contains(s, "refused")
}

// A flood of concurrent connections must not exhaust the hub: it must still
// serve a legitimate user afterwards.
func TestAttack_ConnectionFloodDoesNotDenyService(t *testing.T) {
	h := newHarness(t)

	done := make(chan struct{})
	for i := 0; i < 40; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			c, err := net.DialTimeout("tcp", h.SSHAddr, 2*time.Second)
			if err == nil {
				// Open and idle, without completing a handshake.
				time.Sleep(500 * time.Millisecond)
				c.Close()
			}
		}()
	}
	for i := 0; i < 40; i++ {
		<-done
	}

	// The limiter is per-IP and this test shares 127.0.0.1 with the legitimate
	// client, so a refusal here is the limiter working, not a failure. What must
	// NOT happen is the hub hanging or dying.
	_, err := h.run(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, "true")
	if err != nil && !isTransportRefusal(err) {
		t.Fatalf("hub became unusable after a connection flood: %v", err)
	}
	t.Logf("hub survived the flood (legitimate result: %v)", err)
}

// ---------------------------------------------------------------------------
// Agent-facing attacks
// ---------------------------------------------------------------------------

// An attacker who reaches the agent's stream protocol directly must not be able
// to forge an authorization header.
func TestAttack_ForgedAgentSessionHeader(t *testing.T) {
	agentSrv, err := control.NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)

	// Drive the agent through its real ServeStreams entrypoint, over a real
	// yamux session, rather than reaching into unexported internals.
	hubSide, agentSide := net.Pipe()
	hubSession, err := yamux.Client(hubSide, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer hubSession.Close()
	agentSession, err := yamux.Server(agentSide, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer agentSession.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agentSrv.ServeStreams(ctx, agentSession)

	for _, req := range []control.SessionRequest{
		{Purpose: control.PurposeSession, EndUser: "root", ClientKey: string(ssh.MarshalAuthorizedKey(sshPub))},
		{Purpose: control.PurposeSession, EndUser: "root", ClientKey: ""},
		{Purpose: control.PurposeSession, EndUser: "", ClientKey: "garbage"},
		{Purpose: control.PurposeSession, EndUser: "nonexistent-user", ClientKey: "x"},
	} {
		stream, err := hubSession.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		err = control.RequestSession(stream, req)
		stream.Close()
		if err == nil {
			t.Fatalf("SECURITY: agent accepted a forged header %+v", req)
		}
	}
}

func shortCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func readFileOrEmpty(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func restoreFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if content == nil {
		_ = os.Remove(path)
		return
	}
	_ = os.WriteFile(path, content, 0o600)
}

func appendAuthorizedKey(t *testing.T, path string, pub ssh.PublicKey) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	existing := readFileOrEmpty(t, path)
	updated := append(append([]byte{}, existing...), ssh.MarshalAuthorizedKey(pub)...)
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A client authorized for one backend must not be able to open a raw pipe to a
// DIFFERENT backend by naming it in the direct-tcpip destination.
//
// The hub previously re-routed on the client-supplied DestAddr, so a valid user
// on one node could reach any other node -- including ones only reachable
// through the reverse tunnel.
func TestAttack_DirectTCPIPCannotCrossBackends(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("authorized client should connect: %v", err)
	}
	defer client.Close()

	// Ask the hub to open a channel to a backend this client was not authorized
	// for, and to arbitrary internal addresses.
	for _, dest := range []string{
		"other-backend:22",
		"127.0.0.1:22",
		"10.0.0.1:22",
		"localhost:2222",
	} {
		host, port := splitHostPort(t, dest)
		payload := ssh.Marshal(struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}{host, port, "127.0.0.1", 0})

		ch, _, err := client.OpenChannel("direct-tcpip", payload)
		if err != nil {
			continue // refused, as required
		}
		ch.Close()
		t.Fatalf("SECURITY: hub opened a direct-tcpip channel to %q for a client not authorized for it", dest)
	}
}

func splitHostPort(t *testing.T, addr string) (string, uint32) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port uint32
	for _, c := range portStr {
		port = port*10 + uint32(c-'0')
	}
	return host, port
}
