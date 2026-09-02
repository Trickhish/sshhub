package e2e

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// POSITIVE CONTROL. Every other test in this package asserts that something is
// refused; those assertions are worthless if the system refuses everything. This
// proves a legitimate user can actually get a shell, so the negative results
// below mean what they claim.
func TestHarness_AuthorizedUserCanRunCommand(t *testing.T) {
	h := newHarness(t)

	out, err := h.run(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, "id -un")
	if err != nil {
		t.Fatalf("authorized user must be able to run a command: %v", err)
	}
	got := strings.TrimSpace(out)
	if got != h.EndUser {
		t.Fatalf("session ran as %q, want the route's end_user %q", got, h.EndUser)
	}
	t.Logf("authorized session ran as %q", got)
}

// The session must run as the route's end_user, NOT root. This is the privilege
// escalation from the audit, proven end-to-end through a real session.
func TestSession_RunsAsEndUserNotRoot(t *testing.T) {
	h := newHarness(t)

	out, err := h.run(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, "id -u")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out) == "0" {
		t.Fatal("SECURITY: session ran as root (uid 0) instead of the route's end_user")
	}
	t.Logf("session uid: %s (not root)", strings.TrimSpace(out))
}

// POSITIVE CONTROL for ProxyJump. Tightening direct-tcpip must not break the
// legitimate case: naming the backend you are authorized for has to work, or
// `ssh -J hub node` is broken.
func TestProxyJump_AuthorizedDestinationWorks(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	payload := ssh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{h.Backend, 22, "127.0.0.1", 0})

	ch, reqs, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil {
		t.Fatalf("ProxyJump to the authorized backend %q must be permitted: %v", h.Backend, err)
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	t.Logf("ProxyJump channel to %q opened", h.Backend)
}
