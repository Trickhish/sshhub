package control

import (
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"testing"
)

// findUnprivilegedAccount returns a real non-root local account for testing,
// or "" if none is usable.
func findUnprivilegedAccount(t *testing.T) *account {
	t.Helper()
	for _, name := range []string{"nobody", "daemon", "bin", "games"} {
		acct, err := lookupAccount(name)
		if err == nil && !acct.IsRoot() {
			return acct
		}
	}
	return nil
}

// A session for a non-root account MUST NOT execute as root. The agent runs as
// root, so without an explicit credential the spawned process inherits uid 0.
func TestPrepareCommand_DropsPrivileges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must run as root to verify privilege dropping")
	}
	acct := findUnprivilegedAccount(t)
	if acct == nil {
		t.Skip("no unprivileged account available on this host")
	}

	cmd := exec.Command("/bin/sh", "-c", "id -u")
	prepareCommand(cmd, acct, nil, nil)

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got == "0" {
		t.Fatalf("session for account %q ran as ROOT (uid 0); privilege drop failed", acct.Name)
	}
	if want := itoa(acct.UID); got != want {
		t.Errorf("ran as uid %s, want %s (%s)", got, want, acct.Name)
	}
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b []byte
	for u > 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

// The credential must carry the account's real uid/gid, and must be nil for
// root (where there is nothing to drop).
func TestAccountCredential(t *testing.T) {
	root, err := lookupAccount("root")
	if err != nil {
		t.Skip("no root account on this host")
	}
	if root.credential() != nil {
		t.Error("root credential should be nil (nothing to drop)")
	}

	if acct := findUnprivilegedAccount(t); acct != nil {
		cred := acct.credential()
		if cred == nil {
			t.Fatalf("account %q must have a credential", acct.Name)
		}
		if cred.Uid != acct.UID || cred.Gid != acct.GID {
			t.Errorf("credential = uid %d gid %d, want %d/%d",
				cred.Uid, cred.Gid, acct.UID, acct.GID)
		}
		var _ *syscall.Credential = cred
	}
}

// An unknown account must be rejected, never silently resolved to root.
func TestLookupAccount_FailsClosed(t *testing.T) {
	for _, name := range []string{
		"",
		"definitely-no-such-user-xyz",
		"../root",
		"root/../root",
		"a b",
		"-rf",
		"root:x",
	} {
		if acct, err := lookupAccount(name); err == nil {
			t.Errorf("lookupAccount(%q) MUST fail, got account %+v", name, acct)
		}
	}
}

// authorized_keys must only ever be read from the account's OWN home. A key
// authorized for one account must not satisfy a login as another.
func TestAuthorizedKeysPaths_ScopedToOwnHome(t *testing.T) {
	acct := &account{Name: "alice", Home: "/home/alice"}
	paths := acct.authorizedKeysPaths()
	if len(paths) == 0 {
		t.Fatal("no authorized_keys paths")
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/home/alice/") {
			t.Errorf("path %q escapes the account's home directory", p)
		}
	}

	// The agent process owner's own file must never be consulted.
	if cur, err := user.Current(); err == nil && cur.HomeDir != "/home/alice" {
		for _, p := range paths {
			if strings.HasPrefix(p, cur.HomeDir+"/") {
				t.Errorf("path %q leaks the agent process owner's authorized_keys", p)
			}
		}
	}
}

// Client-supplied environment variables must not be able to hijack the session
// via the dynamic loader or by overriding identity variables.
func TestBuildEnv_FiltersUnsafeClientVars(t *testing.T) {
	acct := &account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh", UID: 1000, GID: 1000}
	env := buildEnv(acct, nil, []string{
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp",
		"BASH_ENV=/tmp/evil",
		"PATH=/tmp",
		"HOME=/root",
		"USER=root",
		"LANG=en_US.UTF-8",
	})

	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "PATH=/tmp", "HOME=/root", "USER=root"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("unsafe client env %q survived filtering:\n%s", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "LANG=en_US.UTF-8") {
		t.Error("benign client env var was dropped")
	}
	if !strings.Contains(joined, "HOME=/home/alice") || !strings.Contains(joined, "USER=alice") {
		t.Errorf("identity vars not set from the resolved account:\n%s", joined)
	}
}

// Without a client-supplied locale, sessions must default to a UTF-8 one.
// Without this, tmux (and other locale-aware programs) deliberately downgrade
// output to ASCII-safe rendering when they see a non-UTF-8 LANG/LC_CTYPE/
// LC_ALL, replacing wide/ambiguous-width glyphs (box-drawing characters, Nerd
// Font icons) with '_'.
func TestBuildEnv_DefaultsToUTF8Locale(t *testing.T) {
	acct := &account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh", UID: 1000, GID: 1000}
	env := buildEnv(acct, nil, nil)

	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "LANG=C.UTF-8") {
		t.Errorf("no default UTF-8 LANG set:\n%s", joined)
	}
	if !strings.Contains(joined, "LC_CTYPE=C.UTF-8") {
		t.Errorf("no default UTF-8 LC_CTYPE set:\n%s", joined)
	}
}

// A client's own locale must win over the default, not be shadowed by it.
// exec.Cmd resolves duplicate keys in Env by taking the LAST occurrence, so
// the default must be added before, never after, client-supplied values.
func TestBuildEnv_ClientLocaleOverridesDefault(t *testing.T) {
	acct := &account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh", UID: 1000, GID: 1000}
	env := buildEnv(acct, nil, []string{"LANG=ja_JP.UTF-8", "LC_CTYPE=ja_JP.UTF-8"})

	lastLANG, lastLCCTYPE := lastValue(env, "LANG"), lastValue(env, "LC_CTYPE")
	if lastLANG != "ja_JP.UTF-8" {
		t.Errorf("effective LANG = %q, want the client's ja_JP.UTF-8 (env: %v)", lastLANG, env)
	}
	if lastLCCTYPE != "ja_JP.UTF-8" {
		t.Errorf("effective LC_CTYPE = %q, want the client's ja_JP.UTF-8 (env: %v)", lastLCCTYPE, env)
	}
}

// LC_ALL must never be set by default: it overrides every other LC_* category
// unconditionally, so defaulting it would clobber a client that set a specific
// category (e.g. LC_TIME) without also setting LC_ALL.
func TestBuildEnv_DoesNotDefaultLCAll(t *testing.T) {
	acct := &account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh", UID: 1000, GID: 1000}
	env := buildEnv(acct, nil, nil)
	for _, kv := range env {
		if strings.HasPrefix(kv, "LC_ALL=") {
			t.Fatalf("LC_ALL must not be set by default, got %q", kv)
		}
	}
}

func lastValue(env []string, key string) string {
	val := ""
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			val = strings.TrimPrefix(kv, prefix)
		}
	}
	return val
}

// The agent's own (root) environment must not leak into a session.
func TestBuildEnv_DoesNotInheritAgentEnvironment(t *testing.T) {
	const marker = "SSHHUB_AGENT_SECRET_MARKER"
	t.Setenv(marker, "leaked")

	acct := &account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh", UID: 1000, GID: 1000}
	for _, kv := range buildEnv(acct, nil, nil) {
		if strings.HasPrefix(kv, marker+"=") {
			t.Fatal("agent process environment leaked into the session")
		}
	}
}
