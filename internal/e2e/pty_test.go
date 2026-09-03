package e2e

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// REGRESSION: window-change requests sent after the shell has started must
// still resize the pty.
//
// The agent's session-request loop used to call the shell/exec handler
// synchronously and return as soon as it finished, which meant nothing read
// further requests off the channel while a process was running. A
// window-change sent mid-session (resizing a terminal during an interactive
// tmux session, for example) was therefore silently dropped: the pty kept
// whatever size it had at "shell" time for the rest of the session.
func TestPTY_WindowChangeAfterShellStartResizesPTY(t *testing.T) {
	h := newHarness(t)

	client, err := h.dial(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	reader := bufio.NewReader(stdout)
	readLine := func() (string, error) {
		type result struct {
			line string
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			l, err := reader.ReadString('\n')
			ch <- result{l, err}
		}()
		select {
		case r := <-ch:
			return r.line, r.err
		case <-time.After(10 * time.Second):
			return "", errTimeout
		}
	}

	// Drain the shell prompt/banner noise until our own marker-based output
	// shows up, since an interactive shell may print a prompt first. The pty
	// has local echo on, so the terminal first echoes back the raw keystrokes
	// (e.g. "echo INITIAL:$(stty size)") before the shell evaluates and prints
	// the actual result (e.g. "INITIAL:24 80"); the echoed line must be
	// skipped or it would match the marker before substitution ever happens.
	waitFor := func(marker string) string {
		t.Helper()
		for i := 0; i < 40; i++ {
			line, err := readLine()
			if err != nil {
				t.Fatalf("read output (waiting for %q): %v", marker, err)
			}
			if strings.Contains(line, "$(") {
				continue // echoed keystrokes, not yet evaluated
			}
			if strings.Contains(line, marker) {
				return line
			}
		}
		t.Fatalf("marker %q never appeared", marker)
		return ""
	}

	// Initial size must match what was requested.
	if _, err := stdin.Write([]byte("echo INITIAL:$(stty size)\n")); err != nil {
		t.Fatal(err)
	}
	initial := waitFor("INITIAL:")
	if !strings.Contains(initial, "INITIAL:24 80") {
		t.Fatalf("initial pty size wrong: %q", initial)
	}

	// Resize AFTER the shell is already running -- this is the case that was
	// broken: nothing was reading window-change requests at this point.
	if err := sess.WindowChange(50, 200); err != nil {
		t.Fatalf("window-change: %v", err)
	}
	// Give the agent a moment to process and apply the resize.
	time.Sleep(300 * time.Millisecond)

	if _, err := stdin.Write([]byte("echo AFTER:$(stty size)\n")); err != nil {
		t.Fatal(err)
	}
	after := waitFor("AFTER:")
	if !strings.Contains(after, "AFTER:50 200") {
		t.Fatalf("pty was not resized after shell start (window-change was dropped): %q", after)
	}

	_, _ = stdin.Write([]byte("exit\n"))
}

// REGRESSION: sessions must get a UTF-8 locale by default.
//
// The agent never set LANG/LC_CTYPE, so a session with no client-supplied
// locale ran under the C/POSIX locale. tmux (and other locale-aware programs)
// deliberately downgrade output when they do not see UTF-8 in LC_ALL,
// LC_CTYPE, or LANG: wide/ambiguous-width glyphs -- box-drawing characters,
// Nerd Font icons -- are replaced with '_' rather than risk misrendering.
func TestPTY_DefaultsToUTF8Locale(t *testing.T) {
	h := newHarness(t)

	out, err := h.run(t, h.Backend, []ssh.AuthMethod{ssh.PublicKeys(h.AuthorizedKey)},
		"echo CHARMAP:$(locale charmap 2>/dev/null)")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "UTF-8") {
		t.Fatalf("session locale is not UTF-8 (tmux would downgrade its output): %q", out)
	}
}

// The exit status of the remote command must still reach the client. This
// exercises ordering in runProcess: it now runs in its own goroutine and must
// send the exit-status message before closing the channel, or a client
// relying on the exit code (as most non-interactive SSH usage does) would see
// a bare EOF instead.
func TestPTY_ExitStatusPropagates(t *testing.T) {
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

	err = sess.Run("exit 7")
	exitErr, ok := err.(*ssh.ExitError)
	if !ok {
		t.Fatalf("expected *ssh.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitStatus() != 7 {
		t.Fatalf("exit status = %d, want 7", exitErr.ExitStatus())
	}
}

var errTimeout = &timeoutErr{}

type timeoutErr struct{}

func (*timeoutErr) Error() string { return "timed out waiting for output" }
