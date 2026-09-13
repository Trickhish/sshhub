package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Trickhish/sshhub/internal/config"
	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type metaStub struct {
	ssh.ConnMetadata
	user string
}

func (m metaStub) User() string { return m.user }

// A jump user with no keys is open by design: the operator has chosen to rely on
// the backend's own sshd for authentication.
func TestOpenJumpUser_AcceptsAnyKey(t *testing.T) {
	s := &Server{cfg: &config.Config{JumpUsers: []config.JumpUser{
		{Name: "open", Backends: []string{"node"}},
	}}}
	if _, err := s.authorize(metaStub{user: "open"}, testKey(t)); err != nil {
		t.Fatalf("open jump user must accept any key: %v", err)
	}
	if !s.hasOpenJumpUser() || !s.isOpenJumpUser("open") {
		t.Fatal("open user not detected")
	}
}

// THE REGRESSION THAT MATTERS: NoClientAuth is set server-wide when any user is
// open, so a keyed user must NOT become reachable without its key.
func TestOpenJumpUser_DoesNotWeakenKeyedUser(t *testing.T) {
	authorized := testKey(t)
	s := &Server{cfg: &config.Config{JumpUsers: []config.JumpUser{
		{Name: "open", Backends: []string{"node"}},
		{Name: "keyed", Keys: []string{string(ssh.MarshalAuthorizedKey(authorized))}, Backends: []string{"node"}},
	}}}

	if s.isOpenJumpUser("keyed") {
		t.Fatal("SECURITY: keyed user treated as open; it would bypass its key requirement")
	}
	if _, err := s.authorize(metaStub{user: "keyed"}, testKey(t)); err == nil {
		t.Fatal("SECURITY: keyed jump user accepted an unauthorized key")
	}
	if _, err := s.authorize(metaStub{user: "keyed"}, authorized); err != nil {
		t.Fatalf("keyed user must still accept its own key: %v", err)
	}
}

// An unknown user is refused even when another user is open.
func TestOpenJumpUser_UnknownUserStillRefused(t *testing.T) {
	s := &Server{cfg: &config.Config{JumpUsers: []config.JumpUser{
		{Name: "open", Backends: []string{"node"}},
	}}}
	if _, err := s.authorize(metaStub{user: "nobody"}, testKey(t)); err == nil {
		t.Fatal("SECURITY: unknown jump user accepted")
	}
	if s.isOpenJumpUser("nobody") {
		t.Fatal("SECURITY: unknown user treated as open")
	}
}

// Open users must still be confined to their granted backends.
func TestOpenJumpUser_StillRestrictedToGrantedBackends(t *testing.T) {
	cfg := &config.Config{
		Listen:   config.Listen{SSH: ":22", Control: ":7000"},
		HostKey:  "/tmp/k",
		Backends: []config.Backend{{ID: "node", Mode: "reverse"}, {ID: "secret", Mode: "reverse"}},
		JumpUsers: []config.JumpUser{
			{Name: "open", Backends: []string{"node"}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("open jump user must be a valid configuration: %v", err)
	}
	granted := map[string]bool{}
	for _, u := range cfg.JumpUsers {
		if u.Name == "open" {
			for _, b := range u.Backends {
				granted[b] = true
			}
		}
	}
	if granted["secret"] {
		t.Fatal("SECURITY: open user granted a backend it was not configured for")
	}
}
