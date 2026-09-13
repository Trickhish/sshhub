package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"time"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

// Connect dials the hub, registers with the given token (and optional backend id),
// and returns a live session and the backend ID assigned by the hub.
// Connect dials the hub and registers. hostKey is the agent's SSH host public
// key in authorized_keys form; the hub pins it so later sessions cannot be
// served by a different endpoint. It may be empty for callers with no SSH
// server of their own.
func Connect(ctx context.Context, hubAddr, backend, token string, tlsConfig *tls.Config) (*yamux.Session, string, error) {
	return ConnectWithHostKey(ctx, hubAddr, backend, token, "", tlsConfig)
}

// ConnectWithHostKey is Connect, additionally advertising the agent's host key.
func ConnectWithHostKey(ctx context.Context, hubAddr, backend, token, hostKey string, tlsConfig *tls.Config) (*yamux.Session, string, error) {
	var conn net.Conn
	var err error
	if tlsConfig != nil {
		d := &net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", hubAddr)
		if err == nil {
			conn = tls.Client(conn, tlsConfig)
		}
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", hubAddr)
	}
	if err != nil {
		return nil, "", fmt.Errorf("dial hub: %w", err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("open yamux session: %w", err)
	}

	assignedBackend, err := register(session, backend, token, hostKey)
	if err != nil {
		session.Close()
		return nil, "", err
	}
	conn.SetDeadline(time.Time{})
	return session, assignedBackend, nil
}

// register opens a control stream, sends the registration request, and returns
// the assigned backend id.
func register(session *yamux.Session, backend, token, hostKey string) (string, error) {
	stream, err := session.OpenStream()
	if err != nil {
		return "", fmt.Errorf("open registration stream: %w", err)
	}
	defer stream.Close()

	req := RegisterRequest{
		Backend: backend,
		Token:   token,
		Version: version.Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		HostKey: hostKey,
	}

	if err := WriteRegister(stream, req); err != nil {
		return "", fmt.Errorf("write register request: %w", err)
	}
	resp, err := ReadResponse(stream)
	if err != nil {
		return "", fmt.Errorf("read register response: %w", err)
	}
	if !resp.OK {
		return "", &RegistrationError{Message: resp.Error}
	}

	// A hub response never triggers executable replacement. Updates are checked
	// independently against signed releases, not hub-selected versions.

	assigned := resp.Backend
	if assigned == "" {
		assigned = backend
	}
	return assigned, nil
}

// Serve bridges incoming streams to the local sshd until the session closes.
func Serve(ctx context.Context, session *yamux.Session, sshdAddr string) error {
	host, _, err := net.SplitHostPort(sshdAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("sshd must be a fixed literal loopback address")
	}
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	slots := make(chan struct{}, 64)
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
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); bridge(stream, sshdAddr) }()
		default:
			stream.Close()
		}
	}
}

// bridge connects a stream to the local sshd and copies bytes in both
// directions.
func bridge(stream net.Conn, sshdAddr string) {
	defer stream.Close()

	sshd, err := net.DialTimeout("tcp", sshdAddr, 5*time.Second)
	if err != nil {
		log.Printf("bridge: dial sshd: %v", err)
		return
	}
	defer sshd.Close()

	errCh := make(chan error, 1)

	// Stream -> sshd (stdin)
	go func() {
		io.Copy(sshd, stream)
		if tc, ok := sshd.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// sshd -> Stream (stdout/stderr)
	go func() {
		_, err := io.Copy(stream, sshd)
		errCh <- err
	}()

	<-errCh
	stream.Close()
	sshd.Close()
}
