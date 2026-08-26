package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

// Connect dials the hub, registers with the given token (and optional backend id),
// and returns a live session and the backend ID assigned by the hub.
func Connect(ctx context.Context, hubAddr, backend, token string, tlsConfig *tls.Config) (*yamux.Session, string, error) {
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

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("open yamux session: %w", err)
	}

	assignedBackend, err := register(session, backend, token)
	if err != nil {
		session.Close()
		return nil, "", err
	}
	return session, assignedBackend, nil
}

// register opens a control stream, sends the registration request, and returns
// the assigned backend id.
func register(session *yamux.Session, backend, token string) (string, error) {
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

	if resp.UpdateAvailable {
		log.Printf("agent: Hub is running version %s (local agent is %s). Downloading update from GitHub...", resp.LatestVersion, version.Version)
		go func() {
			if err := DownloadAndApplyGitHubUpdate(resp.LatestVersion); err != nil {
				log.Printf("agent: github update: %v", err)
			}
		}()
	}

	assigned := resp.Backend
	if assigned == "" {
		assigned = backend
	}
	return assigned, nil
}

// Serve bridges incoming streams to the local sshd until the session closes.
func Serve(ctx context.Context, session *yamux.Session, sshdAddr string) error {
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
		go bridge(stream, sshdAddr)
	}
}

// bridge connects a stream to the local sshd and copies bytes in both
// directions.
func bridge(stream net.Conn, sshdAddr string) {
	defer stream.Close()

	sshd, err := net.Dial("tcp", sshdAddr)
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
