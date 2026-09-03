package e2e

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// remoteTestPath returns a remote path that is unique to this test run.
//
// A fixed path here would collide with a leftover file from a PREVIOUS run: the
// harness creates a new ephemeral Unix account per test, and /tmp persists
// across test invocations. A stale file owned by a since-deleted account makes
// Create (O_TRUNC) fail with a genuine, correct EPERM/EACCES from the kernel --
// nothing to do with sshhub -- which looks exactly like a real bug and cost
// significant time to tell apart from one while developing this test.
func remoteTestPath(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("/tmp/sshhub-e2e-sftp-%s-%d", t.Name(), time.Now().UnixNano())
}

// REGRESSION: the "sftp" subsystem was not handled at all, so every SFTP-based
// transfer (scp -O, sftp, rsync -e ssh with certain options, most GUI SFTP
// clients) failed immediately with "subsystem request failed on channel 0" as
// soon as the client asked for it -- the agent had no case for "subsystem" and
// fell through to refusing the request outright.
func TestSFTP_UploadAndDownloadRoundTrip(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("open sftp subsystem: %v (this is exactly what failed before the fix: "+
			"\"subsystem request failed\")", err)
	}
	defer sftpClient.Close()

	remotePath := remoteTestPath(t)
	t.Cleanup(func() { _ = sftpClient.Remove(remotePath) })

	const payload = "sshhub sftp round trip\n"

	wf, err := sftpClient.Create(remotePath)
	if err != nil {
		t.Fatalf("create remote file: %v", err)
	}
	if _, err := wf.Write([]byte(payload)); err != nil {
		t.Fatalf("write remote file: %v", err)
	}
	if err := wf.Close(); err != nil {
		t.Fatalf("close remote file: %v", err)
	}

	rf, err := sftpClient.Open(remotePath)
	if err != nil {
		t.Fatalf("open remote file for read: %v", err)
	}
	defer rf.Close()

	got, err := io.ReadAll(rf)
	if err != nil {
		t.Fatalf("read remote file: %v", err)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("round-tripped content mismatch: got %q, want %q", got, payload)
	}
}

// The sftp session must run as the route's end_user, exactly like an
// interactive shell or exec session -- the same privilege drop applies
// regardless of which subsystem/command started the process.
func TestSFTP_RunsAsEndUserNotRoot(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("open sftp subsystem: %v", err)
	}
	defer sftpClient.Close()

	// A file created via SFTP must be owned by the resolved account, not root,
	// which is what sftp-server would run as without the privilege drop.
	remotePath := remoteTestPath(t)
	t.Cleanup(func() { _ = sftpClient.Remove(remotePath) })

	wf, err := sftpClient.Create(remotePath)
	if err != nil {
		t.Fatalf("create remote file: %v", err)
	}
	if err := wf.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := sftpClient.Stat(remotePath)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := info.Sys().(*sftp.FileStat)
	if !ok {
		t.Fatalf("unexpected Sys() type: %T", info.Sys())
	}
	if sys.UID == 0 {
		t.Fatalf("SECURITY: file created over sftp is owned by root (uid 0); "+
			"the sftp-server process was not run under the resolved account, want uid != 0, got %d", sys.UID)
	}
}

// An unsupported subsystem must be refused, not silently accepted or crash the
// session -- consistent with how a stock sshd behaves for a subsystem with no
// matching Subsystem directive.
func TestSFTP_UnknownSubsystemRefused(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.RequestSubsystem("not-a-real-subsystem"); err == nil {
		t.Fatal("an unsupported subsystem must be refused")
	}
}
