package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// REGRESSION: a public key must not be usable as a credential.
//
// The agent used to authenticate the hub by accepting the client's public key
// in the SSH *password* field. Public keys are not secret -- they sit in
// authorized_keys files and are served by ssh-keyscan -- so anyone who could
// reach the agent could present a victim's public key and be let in.
//
// The agent must now refuse SSH password authentication outright: authorization
// happens in the framed stream header, on a channel only the hub can write to.
func TestAgent_PublicKeyIsNotABearerToken(t *testing.T) {
	agentSrv, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}

	// A victim's PUBLIC key, as an attacker could trivially obtain it.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	victimPubKey := string(ssh.MarshalAuthorizedKey(sshPub))

	// Drive the agent's SSH layer DIRECTLY, bypassing the stream-header gate.
	// Otherwise the connection dies at the header and the test would pass for
	// an unrelated reason, proving nothing about password auth.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		sConn, chans, reqs, err := ssh.NewServerConn(server, agentSrv.sshConfig)
		if err != nil {
			server.Close()
			return
		}
		defer sConn.Close()
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "no")
		}
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _, _, err = ssh.NewClientConn(client, "agent", &ssh.ClientConfig{
		User: "root",
		// ONLY password auth: if the agent has no PasswordCallback the server
		// refuses the method, so success here means it accepted the public key
		// as a password.
		Auth:            []ssh.AuthMethod{ssh.Password(victimPubKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err == nil {
		t.Fatal("SECURITY: agent accepted a public key presented as a password")
	}
}

// The agent must expose no password authentication at all. Asserted on the
// config directly so it cannot be masked by an earlier failure.
func TestAgent_HasNoPasswordCallback(t *testing.T) {
	agentSrv, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}
	if agentSrv.sshConfig.PasswordCallback != nil {
		t.Fatal("SECURITY: agent must not accept SSH password authentication; " +
			"a public key sent as a password was the original bearer-token flaw")
	}
	if agentSrv.sshConfig.PublicKeyCallback != nil {
		t.Fatal("SECURITY: agent must not authenticate by public key either; " +
			"possession of a public key proves nothing")
	}
}

// An attacker who can reach the agent but cannot produce a valid header must be
// refused, even when naming a real account.
func TestAgent_RejectsUnauthorizedKeyInHeader(t *testing.T) {
	agentSrv, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go agentSrv.handleStream(server)

	err = RequestSession(client, SessionRequest{
		Purpose:   PurposeSession,
		EndUser:   "root",
		ClientKey: string(ssh.MarshalAuthorizedKey(sshPub)),
	})
	if err == nil {
		t.Fatal("SECURITY: agent authorized a key that is not in authorized_keys")
	}
}

// A header naming a non-existent account must be refused, not silently
// downgraded to root.
func TestAgent_RejectsUnknownAccount(t *testing.T) {
	agentSrv, err := NewAgentServer()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go agentSrv.handleStream(server)

	err = RequestSession(client, SessionRequest{
		Purpose:   PurposeSession,
		EndUser:   "definitely-no-such-user-xyz",
		ClientKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample test",
	})
	if err == nil {
		t.Fatal("SECURITY: agent accepted a session for a non-existent account")
	}
}
