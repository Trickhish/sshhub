package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

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
			clientKeyStr := string(password)
			targetUser := conn.User()
			if targetUser == "" {
				targetUser = "root"
			}

			if isKeyAuthorized(targetUser, clientKeyStr) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"user": targetUser,
					},
				}, nil
			}
			return nil, fmt.Errorf("unauthorized key for user %s", targetUser)
		},
		// PublicKeyCallback also accepts direct public key authentication if connected directly.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			targetUser := conn.User()
			if targetUser == "" {
				targetUser = "root"
			}
			if isKeyAuthorized(targetUser, string(ssh.MarshalAuthorizedKey(key))) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"user": targetUser,
					},
				}, nil
			}
			return nil, fmt.Errorf("unauthorized key for user %s", targetUser)
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
		go handleSessionChannel(ch, chReqs, sConn.User())
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

func handleSessionChannel(ch ssh.Channel, reqs <-chan *ssh.Request, username string) {
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
			shell := getDefaultShell(username)
			cmd := exec.Command(shell)
			cmd.Env = buildEnv(username, ptyReq, envVars)
			runProcess(ch, cmd, ptyReq, &ptyFile, &cmdMutex)
			return

		case "exec":
			var ep execPayload
			if err := ssh.Unmarshal(req.Payload, &ep); err == nil {
				req.Reply(true, nil)
				shell := getDefaultShell(username)
				cmd := exec.Command(shell, "-c", ep.Command)
				cmd.Env = buildEnv(username, ptyReq, envVars)
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

func buildEnv(username string, ptyReq *ptyReqPayload, extraEnv []string) []string {
	env := os.Environ()
	env = append(env, fmt.Sprintf("USER=%s", username))
	env = append(env, fmt.Sprintf("LOGNAME=%s", username))

	home := "/root"
	if username != "root" && username != "" {
		if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
			home = u.HomeDir
		} else {
			home = "/home/" + username
		}
	}
	env = append(env, fmt.Sprintf("HOME=%s", home))

	if ptyReq != nil && ptyReq.Term != "" {
		env = append(env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	} else {
		env = append(env, "TERM=xterm-256color")
	}

	env = append(env, extraEnv...)
	return env
}

func getDefaultShell(username string) string {
	if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
		// shell lookup
	}
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

func isKeyAuthorized(username, clientKeyStr string) bool {
	if clientKeyStr == "" {
		return false
	}
	clientKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(clientKeyStr))
	if err != nil {
		return false
	}
	clientKeyBytes := clientKey.Marshal()

	authKeysPath := getAuthorizedKeysPath(username)
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		log.Printf("agent: read %s: %v", authKeysPath, err)
		return false
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
		if string(key.Marshal()) == string(clientKeyBytes) {
			return true
		}
	}
	return false
}

func getAuthorizedKeysPath(username string) string {
	if username == "root" || username == "" {
		return "/root/.ssh/authorized_keys"
	}
	if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	}
	return filepath.Join("/home", username, ".ssh", "authorized_keys")
}
