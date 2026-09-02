package e2e

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// REGRESSION: a client whose agent holds several keys must not be blocked.
//
// OpenSSH offers every key in the agent in turn. The rate limiter originally
// counted each rejected OFFER as a failure, so a client with 6 agent keys burnt
// 6 of its 10-failure budget per connection and was blocked for 15 minutes
// after two ordinary attempts -- surfacing as
// "kex_exchange_identification: Connection closed by remote host".
//
// Failures are now counted once per connection.
func TestRegression_ClientWithManyAgentKeysIsNotBlocked(t *testing.T) {
	h := newHarness(t)

	// Six unauthorized keys, then the authorized one -- a realistic agent.
	var auth []ssh.AuthMethod
	var decoys []ssh.Signer
	for i := 0; i < 6; i++ {
		s, _ := generateKey(t)
		decoys = append(decoys, s)
	}
	auth = append(auth, ssh.PublicKeys(append(decoys, h.AuthorizedKey)...))

	// Several consecutive logins, as a user would make over a work session.
	for attempt := 1; attempt <= 4; attempt++ {
		out, err := h.run(t, h.Backend, auth, "id -un")
		if err != nil {
			t.Fatalf("attempt %d: legitimate client with 6 agent keys was refused: %v\n"+
				"(if this is a transport-level close, the rate limiter is counting "+
				"key offers instead of connections)", attempt, err)
		}
		if strings.TrimSpace(out) != h.EndUser {
			t.Fatalf("attempt %d: ran as %q, want %q", attempt, strings.TrimSpace(out), h.EndUser)
		}
	}
	t.Log("4 consecutive logins with 6 decoy keys each: all succeeded")
}

// A client that only ever offers wrong keys must still eventually be blocked --
// the fix above must not disable brute-force protection.
func TestRegression_WrongKeysStillBlocked(t *testing.T) {
	h := newHarness(t)

	blocked := false
	for i := 0; i < 30; i++ {
		bad, _ := generateKey(t)
		_, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(bad)})
		if err == nil {
			t.Fatal("SECURITY: an unauthorized key authenticated")
		}
		if isTransportRefusal(err) {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("repeated failed connections were never throttled")
	} else {
		t.Log("brute-force protection still engages")
	}
}
