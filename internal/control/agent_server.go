package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
)

// AgentServer serves SSH sessions directly on the endpoint with PTY allocation
// and verifies client public keys against local authorized_keys.
type AgentServer struct {
	sshConfig *ssh.ServerConfig
}

// NewAgentServer creates an AgentServer with an ephemeral host key.
func NewAgentServer() (*AgentServer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create agent signer: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		// PasswordCallback receives the client's public key string in the password field
		// from the hub, and checks if it is in authorized_keys for the target user.
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			targetUser := conn.User()
			if targetUser == "" {
				targetUser = "root"
			}

			// Fail closed on an unknown account rather than falling back to root.
			acct, err := lookupAccount(targetUser)
			if err != nil {
				log.Printf("agent: reject session: %v", err)
				return nil, fmt.Errorf("unauthorized")
			}

			if isKeyAuthorized(acct, string(password)) {
				return &ssh.Permissions{
					Extensions: map[string]string{"user": acct.Name},
				}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
		// PublicKeyCallback also accepts direct public key authentication if connected directly.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			targetUser := conn.User()
			if targetUser == "" {
				targetUser = "root"
			}

			acct, err := lookupAccount(targetUser)
			if err != nil {
				log.Printf("agent: reject session: %v", err)
				return nil, fmt.Errorf("unauthorized")
			}

			if isKeyAuthorized(acct, string(ssh.MarshalAuthorizedKey(key))) {
				return &ssh.Permissions{
					Extensions: map[string]string{"user": acct.Name},
				}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	sshConfig.AddHostKey(signer)

	return &AgentServer{
		sshConfig: sshConfig,
	}, nil
}

// ServeStreams accepts incoming streams from the yamux session and handles SSH sessions.
func (a *AgentServer) ServeStreams(ctx context.Context, session *yamux.Session) error {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept stream: %w", err)
			}
		}
		go a.handleStream(stream)
	}
}

func (a *AgentServer) handleStream(stream net.Conn) {
	defer stream.Close()

	sConn, chans, reqs, err := ssh.NewServerConn(stream, a.sshConfig)
	if err != nil {
		log.Printf("agent: handshake check failed: %v", err)
		return
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		// Re-resolve from the authenticated identity. Failing here means the
		// account vanished between auth and channel open; refuse rather than
		// serve the session with an unresolved (and therefore root) identity.
		acct, err := lookupAccount(sConn.User())
		if err != nil {
			log.Printf("agent: reject channel: %v", err)
			newCh.Reject(ssh.Prohibited, "unauthorized")
			continue
		}

		ch, chReqs, err := newCh.Accept()
		if err != nil {
			log.Printf("agent: accept channel: %v", err)
			return
		}
		go handleSessionChannel(ch, chReqs, acct)
	}
}

type ptyReqPayload struct {
	Term     string
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type windowChangePayload struct {
	Width    uint32
	Height   uint32
	WidthPx  uint32
	HeightPx uint32
}

type execPayload struct {
	Command string
}

type envPayload struct {
	Name  string
	Value string
}

func handleSessionChannel(ch ssh.Channel, reqs <-chan *ssh.Request, acct *account) {
	defer ch.Close()

	var (
		ptyReq   *ptyReqPayload
		ptyFile  *os.File
		cmdMutex sync.Mutex
		envVars  []string
	)

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyReqPayload
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				ptyReq = &p
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}

		case "window-change":
			var wc windowChangePayload
			if err := ssh.Unmarshal(req.Payload, &wc); err == nil {
				cmdMutex.Lock()
				if ptyFile != nil {
					_ = pty.Setsize(ptyFile, &pty.Winsize{
						Rows: uint16(wc.Height),
						Cols: uint16(wc.Width),
						X:    uint16(wc.WidthPx),
						Y:    uint16(wc.HeightPx),
					})
				}
				cmdMutex.Unlock()
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}

		case "env":
			var env envPayload
			if err := ssh.Unmarshal(req.Payload, &env); err == nil {
				envVars = append(envVars, fmt.Sprintf("%s=%s", env.Name, env.Value))
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}

		case "shell":
			req.Reply(true, nil)
			cmd := exec.Command(acct.Shell)
			prepareCommand(cmd, acct, ptyReq, envVars)
			runProcess(ch, cmd, ptyReq, &ptyFile, &cmdMutex)
			return

		case "exec":
			var ep execPayload
			if err := ssh.Unmarshal(req.Payload, &ep); err == nil {
				req.Reply(true, nil)
				cmd := exec.Command(acct.Shell, "-c", ep.Command)
				prepareCommand(cmd, acct, ptyReq, envVars)
				runProcess(ch, cmd, ptyReq, &ptyFile, &cmdMutex)
				return
			}
			req.Reply(false, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

func runProcess(ch ssh.Channel, cmd *exec.Cmd, ptyReq *ptyReqPayload, ptyFile **os.File, m *sync.Mutex) {
	if ptyReq != nil {
		m.Lock()
		f, err := pty.Start(cmd)
		if err != nil {
			m.Unlock()
			sendExitStatus(ch, 1)
			return
		}
		*ptyFile = f
		_ = pty.Setsize(f, &pty.Winsize{
			Rows: uint16(ptyReq.Height),
			Cols: uint16(ptyReq.Width),
			X:    uint16(ptyReq.WidthPx),
			Y:    uint16(ptyReq.HeightPx),
		})
		m.Unlock()

		go func() {
			_, _ = io.Copy(f, ch)
		}()
		_, _ = io.Copy(ch, f)
		_ = f.Close()
	} else {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			sendExitStatus(ch, 1)
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			sendExitStatus(ch, 1)
			return
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			sendExitStatus(ch, 1)
			return
		}

		if err := cmd.Start(); err != nil {
			sendExitStatus(ch, 1)
			return
		}

		go func() {
			_, _ = io.Copy(stdin, ch)
			_ = stdin.Close()
		}()
		go func() {
			_, _ = io.Copy(ch.Stderr(), stderr)
		}()
		_, _ = io.Copy(ch, stdout)
	}

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	sendExitStatus(ch, uint32(exitCode))
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	msg := struct{ Status uint32 }{Status: code}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&msg))
}

// prepareCommand configures a session process to run AS the resolved account:
// it drops privileges, sets the working directory to the account's home, and
// builds a clean environment.
//
// The agent itself runs as root. Without the credential below every session --
// including one for an unprivileged account -- would execute as root.
func prepareCommand(cmd *exec.Cmd, acct *account, ptyReq *ptyReqPayload, extraEnv []string) {
	if cred := acct.credential(); cred != nil {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = cred
	}

	// Start in the account's home, but fall back to / if it does not exist
	// (e.g. nobody's /nonexistent). A missing Dir makes exec fail outright.
	cmd.Dir = "/"
	if fi, err := os.Stat(acct.Home); err == nil && fi.IsDir() {
		cmd.Dir = acct.Home
	}

	cmd.Env = buildEnv(acct, ptyReq, extraEnv)
}

// buildEnv constructs the environment for a session process.
//
// It deliberately does NOT inherit the agent's os.Environ(): the agent runs as
// root under systemd, and leaking its environment into an unprivileged session
// discloses agent configuration and can alter the target's behaviour.
func buildEnv(acct *account, ptyReq *ptyReqPayload, extraEnv []string) []string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if !acct.IsRoot() {
		path = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
	}

	env := []string{
		fmt.Sprintf("USER=%s", acct.Name),
		fmt.Sprintf("LOGNAME=%s", acct.Name),
		fmt.Sprintf("HOME=%s", acct.Home),
		fmt.Sprintf("SHELL=%s", acct.Shell),
		fmt.Sprintf("PATH=%s", path),
	}

	if ptyReq != nil && ptyReq.Term != "" {
		env = append(env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	} else {
		env = append(env, "TERM=xterm-256color")
	}

	// Client-supplied env vars are appended last but filtered: variables that
	// influence the dynamic loader would let a client subvert the session.
	for _, kv := range extraEnv {
		if isUnsafeEnv(kv) {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// isUnsafeEnv reports whether a client-supplied environment variable must be
// dropped. LD_* and friends can hijack execution via the dynamic loader.
func isUnsafeEnv(kv string) bool {
	name, _, ok := strings.Cut(kv, "=")
	if !ok {
		return true
	}
	switch {
	case strings.HasPrefix(name, "LD_"),
		strings.HasPrefix(name, "BASH_ENV"),
		name == "IFS",
		name == "PATH",
		name == "SHELL",
		name == "HOME",
		name == "USER",
		name == "LOGNAME":
		return true
	}
	return false
}

// isKeyAuthorized reports whether clientKeyStr appears in the authorized_keys
// of the given resolved account.
//
// Only files inside that account's own home directory are consulted, so a key
// authorized for one account can never satisfy a login as another.
func isKeyAuthorized(acct *account, clientKeyStr string) bool {
	if clientKeyStr == "" || acct == nil {
		return false
	}
	clientKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientKeyStr))
	if err != nil {
		log.Printf("agent: parse client public key failed: %v", err)
		return false
	}
	clientKeyBytes := clientKey.Marshal()
	clientFp := ssh.FingerprintSHA256(clientKey)

	paths := acct.authorizedKeysPaths()
	for _, authKeysPath := range paths {
		data, err := os.ReadFile(authKeysPath)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			if subtle.ConstantTimeCompare(key.Marshal(), clientKeyBytes) == 1 {
				log.Printf("agent: authorized key %s for account %s (matched in %s)",
					clientFp, acct.Name, authKeysPath)
				return true
			}
		}
	}

	log.Printf("agent: key %s not authorized for account %s (checked: %v)", clientFp, acct.Name, paths)
	return false
}
