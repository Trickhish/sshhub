package control

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestControlPlaneRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry := NewRegistry()
	server := NewServer(registry, func(token, requestedBackend string) (string, bool) {
		if token == "secret-token" {
			return "db1", true
		}
		return "", false
	}, nil)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ListenAndServe(ctx, addr) }()

	// Fake sshd: echo server the agent will bridge to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	// Give the hub listener a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Agent connects without specifying backend ID, hub assigns "db1"
	session, assignedBackend, err := Connect(ctx, addr, "", "secret-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if assignedBackend != "db1" {
		t.Fatalf("expected assigned backend db1, got %q", assignedBackend)
	}

	go Serve(ctx, session, echoLn.Addr().String())

	// Wait for the registry to record the backend.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := registry.Open(ctx, "db1"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	stream, err := registry.Open(ctx, "db1")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	msg := "hello sshhub"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func TestConnectRejectsBadToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	registry := NewRegistry()
	server := NewServer(registry, func(token, requestedBackend string) (string, bool) {
		if token == "secret" {
			return "db1", true
		}
		return "", false
	}, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, addr) }()
	time.Sleep(100 * time.Millisecond)

	if _, _, err := Connect(ctx, addr, "db1", "wrong", nil); err == nil {
		t.Fatal("expected registration error")
	}
}
