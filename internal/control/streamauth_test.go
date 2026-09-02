package control

import (
	"net"
	"strings"
	"testing"
	"time"
)

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return c1, c2
}

func TestStreamAuth_RoundTrip(t *testing.T) {
	hub, agent := pipePair(t)

	go func() {
		req, err := AcceptSession(agent)
		if err != nil {
			return
		}
		if req.EndUser != "deploy" || req.Purpose != PurposeSession {
			_ = ReplySession(agent, false, "unexpected")
			return
		}
		_ = ReplySession(agent, true, "")
	}()

	err := RequestSession(hub, SessionRequest{
		Purpose:   PurposeSession,
		EndUser:   "deploy",
		ClientKey: "ssh-ed25519 AAAA test",
	})
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestStreamAuth_RefusalIsAnError(t *testing.T) {
	hub, agent := pipePair(t)
	go func() {
		_, _ = AcceptSession(agent)
		_ = ReplySession(agent, false, "unauthorized")
	}()

	if err := RequestSession(hub, SessionRequest{Purpose: PurposeSession, EndUser: "root"}); err == nil {
		t.Fatal("a refusal MUST surface as an error, not be silently ignored")
	}
}

// The header must be read with exact framing: bytes after it belong to the SSH
// handshake and must remain in the stream. A buffering reader here would eat
// them and break every session.
func TestStreamAuth_LeavesTrailingBytesIntact(t *testing.T) {
	hub, agent := pipePair(t)
	const trailer = "SSH-2.0-OpenSSH_9.6\r\n"

	done := make(chan string, 1)
	go func() {
		if _, err := AcceptSession(agent); err != nil {
			done <- "accept: " + err.Error()
			return
		}
		if err := ReplySession(agent, true, ""); err != nil {
			done <- "reply: " + err.Error()
			return
		}
		buf := make([]byte, len(trailer))
		if _, err := readFullDeadline(agent, buf); err != nil {
			done <- "read trailer: " + err.Error()
			return
		}
		done <- string(buf)
	}()

	if err := RequestSession(hub, SessionRequest{Purpose: PurposeSession, EndUser: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Write([]byte(trailer)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-done:
		if got != trailer {
			t.Fatalf("trailing bytes corrupted: got %q want %q", got, trailer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: header read consumed the trailing SSH banner")
	}
}

func readFullDeadline(c net.Conn, buf []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// A peer speaking a different protocol version must get a clear, actionable
// error rather than hanging or silently misparsing.
func TestStreamAuth_VersionMismatchIsDiagnosable(t *testing.T) {
	hub, agent := pipePair(t)
	go func() {
		frame := append([]byte(streamMagic), 99) // bogus version
		frame = append(frame, 0, 0, 0, 2, '{', '}')
		_, _ = hub.Write(frame)
	}()

	_, err := AcceptSession(agent)
	if err == nil {
		t.Fatal("version mismatch MUST be rejected")
	}
	if !strings.Contains(err.Error(), "upgraded together") {
		t.Errorf("error should tell the operator to upgrade both sides, got: %v", err)
	}
}

// A peer that is not an sshhub endpoint (e.g. something speaking raw SSH at the
// agent) must be rejected rather than misinterpreted.
func TestStreamAuth_RejectsNonSSHHubPeer(t *testing.T) {
	hub, agent := pipePair(t)
	go func() { _, _ = hub.Write([]byte("SSH-2.0-OpenSSH_9.6\r\nxxxxx")) }()

	if _, err := AcceptSession(agent); err == nil {
		t.Fatal("a non-sshhub peer MUST be rejected")
	}
}
