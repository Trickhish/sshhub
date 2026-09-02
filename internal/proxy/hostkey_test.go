package proxy

import (
	"testing"

	"github.com/Trickhish/sshhub/internal/config"
	"github.com/Trickhish/sshhub/internal/control"
	"golang.org/x/crypto/ssh"
)

// With no host key from config and none advertised at registration, the hub
// must REFUSE rather than accept any key. Accepting any key would let a
// compromised control session substitute a different endpoint.
func TestAgentHostKey_FailsClosedWhenUnknown(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{},
		registry: control.NewRegistry(),
	}
	_, err := s.agentHostKeyCallback(&config.Backend{ID: "unknown", Mode: "reverse"})
	if err == nil {
		t.Fatal("SECURITY: hub accepted a backend with no known host key")
	}
}

// An operator-configured host_key takes precedence over anything advertised.
func TestAgentHostKey_ConfigPinWins(t *testing.T) {
	signer, _ := generateKey(t)
	pinned := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	s := &Server{cfg: &config.Config{}, registry: control.NewRegistry()}
	cb, err := s.agentHostKeyCallback(&config.Backend{
		ID:      "b",
		Mode:    "reverse",
		HostKey: pinned,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cb == nil {
		t.Fatal("expected a host key callback")
	}

	// The pinned key is accepted...
	if err := cb("b", fakeAddrHK("1.2.3.4:22"), signer.PublicKey()); err != nil {
		t.Errorf("pinned key should be accepted: %v", err)
	}
	// ...and a different key is not.
	other, _ := generateKey(t)
	if err := cb("b", fakeAddrHK("1.2.3.4:22"), other.PublicKey()); err == nil {
		t.Fatal("SECURITY: a host key other than the pinned one was accepted")
	}
}

// A malformed configured host key must be an error, not silently ignored.
func TestAgentHostKey_MalformedConfigRejected(t *testing.T) {
	s := &Server{cfg: &config.Config{}, registry: control.NewRegistry()}
	if _, err := s.agentHostKeyCallback(&config.Backend{
		ID:      "b",
		Mode:    "reverse",
		HostKey: "not-a-key",
	}); err == nil {
		t.Fatal("malformed host_key must be rejected")
	}
}

type fakeAddrHK string

func (f fakeAddrHK) Network() string { return "tcp" }
func (f fakeAddrHK) String() string  { return string(f) }
