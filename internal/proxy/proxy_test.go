package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/Trickhish/sshhub/internal/config"
	"golang.org/x/crypto/ssh"
	"testing"
)

// Full SSH transport/authentication coverage lives in internal/e2e against
// OpenSSH, rather than a stub implementing the removed identity protocol.
func TestJumpKeyOptionsFailClosed(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JumpUsers: []config.JumpUser{{Name: "alice", Keys: []string{`command="true" ` + string(ssh.MarshalAuthorizedKey(key))}, Backends: []string{"node"}}}}
	if cfg.Validate() == nil {
		t.Fatal("restricted keys must not silently become unrestricted jump keys")
	}
}
