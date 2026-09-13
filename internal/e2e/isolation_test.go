package e2e

import (
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
	"time"
)

func TestIsolation_JumpKeyDoesNotAuthenticateBackend(t *testing.T) {
	h := newHarness(t)
	attacker, _ := generateKey(t)
	// The legitimate jump connection is established by dialInner. A different
	// inner key still cannot authenticate, even though the hub permits the pipe.
	if c, err := h.dialInner(t, []ssh.AuthMethod{ssh.PublicKeys(attacker)}); err == nil {
		c.Close()
		t.Fatal("backend accepted unauthenticated identity")
	}
	if c, err := h.dialInner(t, nil); err == nil {
		c.Close()
		t.Fatal("backend accepted none authentication")
	}
	if c, err := h.dialInner(t, []ssh.AuthMethod{ssh.Password(string(ssh.MarshalAuthorizedKey(h.AuthorizedKey.PublicKey())))}); err == nil {
		c.Close()
		t.Fatal("public key accepted as password")
	}
}

func TestIsolation_HubCannotSubstituteBackendHostKey(t *testing.T) {
	h := newHarness(t)
	c, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.Dial("tcp", h.Backend+":22")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	wrong, _ := generateKey(t)
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, _, _, err = ssh.NewClientConn(raw, h.Backend, &ssh.ClientConfig{User: h.EndUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)}, HostKeyCallback: ssh.FixedHostKey(wrong.PublicKey())})
	if err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("expected host key rejection: %v", err)
	}
}

func TestIsolation_HubRejectsAllSessionChannels(t *testing.T) {
	h := newHarness(t)
	c, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s, err := c.NewSession(); err == nil {
		s.Close()
		t.Fatal("hub accepted a direct session")
	}
}
