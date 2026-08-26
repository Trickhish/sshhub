package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/hashicorp/yamux"
)

// Connect dials the hub, registers the backend, and returns a live session.
func Connect(ctx context.Context, hubAddr, backend, token string, tlsConfig *tls.Config) (*yamux.Session, error) {
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
		return nil, fmt.Errorf("dial hub: %w", err)
	}

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open yamux session: %w", err)
	}

	if err := register(session, backend, token); err != nil {
		session.Close()
		return nil, err
	}
	return session, nil
}

// register opens a control stream, sends the registration request, and checks
// the hub's response.
func register(session *yamux.Session, backend, token string) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open registration stream: %w", err)
	}
	defer stream.Close()

	if err := WriteRegister(stream, RegisterRequest{Backend: backend, Token: token}); err != nil {
		return fmt.Errorf("write register request: %w", err)
	}
	resp, err := ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("read register response: %w", err)
	}
	if !resp.OK {
		return &RegistrationError{Message: resp.Error}
	}
	return nil
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

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(sshd, stream)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(stream, sshd)
		errCh <- err
	}()
	<-errCh
	stream.Close()
	sshd.Close()
	<-errCh
}
