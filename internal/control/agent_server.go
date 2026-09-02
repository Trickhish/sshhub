package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	hostKey   ssh.Signer
}

// DefaultHostKeyPath is where the agent persists its SSH host key, giving it a
// stable identity the hub can pin across restarts.
const DefaultHostKeyPath = "/var/lib/sshhub/agent_host_key"

// NewAgentServer creates an AgentServer with an ephemeral host key.
//
// Prefer NewAgentServerWithHostKey: an ephemeral key changes on every restart,
// so it cannot be pinned. This constructor remains for tests.
func NewAgentServer() (*AgentServer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create agent signer: %w", err)
	}
	return newAgentServer(signer)
}

// NewAgentServerWithHostKey creates an AgentServer using a persistent host key
// loaded from path, generating and storing one if absent.
func NewAgentServerWithHostKey(path string) (*AgentServer, error) {
	signer, err := loadOrCreateHostKey(path)
	if err != nil {
		return nil, err
	}
	return newAgentServer(signer)
}

// HostKey returns the agent's public host key in authorized_keys form, which
// the hub records at registration and pins on subsequent connections.
func (a *AgentServer) HostKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(a.hostKey.PublicKey())))
}

// loadOrCreateHostKey reads an Ed25519 host key from path, creating it if it
// does not exist. The key file is owner-only.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse agent host key %s: %w", path, err)
		}
		return signer, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read agent host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "sshhub-agent")
	if err != nil {
		return nil, fmt.Errorf("marshal agent host key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write agent host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create agent signer: %w", err)
	}
	return signer, nil
}

func newAgentServer(signer ssh.Signer) (*AgentServer, error) {

	sshConfig := &ssh.ServerConfig{
		// Authorization already happened in the stream header (see streamauth.go),
		// on a channel only the hub can write to. The SSH layer here just carries
		// the session; it performs no authentication of its own.
		//
		// PasswordCallback is intentionally ABSENT. It previously accepted the
		// client's public key as a password, which made a published public key a
		// bearer token: anyone who could reach the agent could present a victim's
		// key and be let in. PublicKeyCallback is absent for the same reason --
		// possession of a public key proves nothing.
		NoClientAuth: true,
	}
	sshConfig.AddHostKey(signer)

	return &AgentServer{
		sshConfig: sshConfig,
		hostKey:   signer,
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

	// Authorize BEFORE any SSH machinery runs. The frame arrived on the control
	// session this agent dialled out and authenticated, so it provably came from
	// the hub.
	acct, purpose, err := a.authorizeStream(stream)
	if err != nil {
		log.Printf("agent: %v", err)
		return
	}

	// A verify probe only asks for the verdict; the hub closes the stream.
	if purpose == PurposeVerify {
		return
	}

	sConn, chans, reqs, err := ssh.NewServerConn(stream, a.sshConfig)
	if err != nil {
		log.Printf("agent: handshake failed: %v", err)
		return
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels supported")
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

// authorizeStream reads and validates the hub's authorization header.
//
// The agent is the authority here: it independently confirms the account exists
// on THIS host and that the named key is in that account's authorized_keys. The
// hub's assertion selects who to check, it does not decide the outcome.
func (a *AgentServer) authorizeStream(stream net.Conn) (*account, string, error) {
	req, err := AcceptSession(stream)
	if err != nil {
		return nil, "", fmt.Errorf("stream authorization: %w", err)
	}

	endUser := req.EndUser
	if endUser == "" {
		endUser = "root"
	}

	acct, err := lookupAccount(endUser)
	if err != nil {
		_ = ReplySession(stream, false, "unauthorized")
		return nil, "", fmt.Errorf("reject session: %w", err)
	}

	if !isKeyAuthorized(acct, req.ClientKey) {
		_ = ReplySession(stream, false, "unauthorized")
		return nil, "", fmt.Errorf("reject session: key not authorized for account %q", acct.Name)
	}

	if err := ReplySession(stream, true, ""); err != nil {
		return nil, "", fmt.Errorf("reply: %w", err)
	}
	return acct, req.Purpose, nil
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
