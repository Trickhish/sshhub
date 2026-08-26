package control

import (
	"net"
	"testing"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

func TestUpdateNotification(t *testing.T) {
	registry := NewRegistry()
	resolveToken := func(token, requested string) (string, bool) {
		if token == "secret-token" {
			return "node1", true
		}
		return "", false
	}
	server := NewServer(registry, resolveToken, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session, err := yamux.Server(c, yamux.DefaultConfig())
				if err != nil {
					c.Close()
					return
				}
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				req, _ := ReadRegister(stream)
				if req.Token == "secret-token" {
					_ = WriteResponse(stream, RegisterResponse{
						OK:              true,
						Backend:         "node1",
						UpdateAvailable: req.Version != version.Version,
						LatestVersion:   version.Version,
					})
				}
			}(conn)
		}
	}()

	_ = server // used

	// Agent connects with old version
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	err = WriteRegister(stream, RegisterRequest{
		Token:   "secret-token",
		Version: "0.1.0-old",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ReadResponse(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.UpdateAvailable {
		t.Fatalf("expected UpdateAvailable true, got false")
	}
	if resp.LatestVersion != version.Version {
		t.Fatalf("got %s, want %s", resp.LatestVersion, version.Version)
	}
}
