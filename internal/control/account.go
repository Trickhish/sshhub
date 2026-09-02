package control

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// account is a resolved local Unix account that a session will run as.
//
// Every privilege-relevant value (uid/gid, home directory, authorized_keys
// path, login shell) is derived from a SINGLE user.Lookup so they cannot drift
// apart. In particular the authorized_keys file consulted during authorization
// is always the one belonging to the same uid the process is later spawned as.
type account struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
	Shell  string
}

// lookupAccount resolves a Unix account by name.
//
// It fails closed: an unknown account is an error, never a silent fallback to
// root. The name originates from the hub's route configuration (end_user), but
// is treated as untrusted input here regardless.
func lookupAccount(name string) (*account, error) {
	if name == "" {
		return nil, fmt.Errorf("empty account name")
	}
	// Reject anything that could not be a legitimate account name before it
	// reaches the resolver or is used to build a path.
	if strings.ContainsAny(name, " \t\n/:,\\") || strings.HasPrefix(name, "-") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}

	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("no such account %q on this host: %w", name, err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("account %q has non-numeric uid %q", name, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("account %q has non-numeric gid %q", name, u.Gid)
	}

	if u.HomeDir == "" {
		return nil, fmt.Errorf("account %q has no home directory", name)
	}

	acct := &account{
		Name:  u.Username,
		UID:   uint32(uid),
		GID:   uint32(gid),
		Home:  u.HomeDir,
		Shell: loginShell(u.Username),
	}

	// Supplementary groups. Without these a dropped process would lose group
	// memberships it legitimately has (e.g. docker, sudo, wheel).
	if gids, err := u.GroupIds(); err == nil {
		for _, g := range gids {
			n, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				continue
			}
			acct.Groups = append(acct.Groups, uint32(n))
		}
	}

	return acct, nil
}

// IsRoot reports whether this account is uid 0.
func (a *account) IsRoot() bool { return a.UID == 0 }

// credential returns the syscall credential used to drop privileges when
// spawning a session process. It returns nil for root, where there is nothing
// to drop and setting a credential is a no-op.
func (a *account) credential() *syscall.Credential {
	if a.IsRoot() {
		return nil
	}
	return &syscall.Credential{
		Uid:    a.UID,
		Gid:    a.GID,
		Groups: a.Groups,
	}
}

// authorizedKeysPaths returns the authorized_keys files to consult for this
// account, in order.
//
// These are ONLY ever inside the account's own home directory. Earlier versions
// also probed /home/<name> by convention and fell back to the *agent process*
// owner's file, which meant a key authorized for one account could satisfy a
// login as another.
func (a *account) authorizedKeysPaths() []string {
	sshDir := filepath.Join(a.Home, ".ssh")
	return []string{
		filepath.Join(sshDir, "authorized_keys"),
		filepath.Join(sshDir, "authorized_keys2"),
	}
}

// loginShell returns the account's login shell from /etc/passwd, falling back
// to a sensible default. It deliberately does NOT consult $SHELL, which belongs
// to the agent process (running as root), not to the target account.
func loginShell(username string) string {
	if shell := passwdShell(username); shell != "" {
		return shell
	}
	for _, candidate := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/bin/sh"
}

// passwdShell reads the login shell for username from /etc/passwd.
// os/user does not expose the shell field, so it is parsed directly.
func passwdShell(username string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] != username {
			continue
		}
		shell := strings.TrimSpace(fields[6])
		if shell == "" || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
			return ""
		}
		return shell
	}
	return ""
}
