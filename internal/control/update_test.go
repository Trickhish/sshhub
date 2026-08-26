package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Trickhish/sshhub/internal/version"
	"github.com/hashicorp/yamux"
)

func TestAutoUpdateOverControlPlane(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sshhub-agent")
	dummyBinaryContent := []byte("#!/bin/sh\necho updated v2\n")
	if err := os.WriteFile(binPath, dummyBinaryContent, 0o755); err != nil {
		t.Fatal(err)
	}

	// Sign the binary
	sum := sha256.Sum256(dummyBinaryContent)
	shaHex := hex.EncodeToString(sum[:])
	testPrivKeyHex := "a5a741f7ed783104b06dee91937d1f48a6124b9db60ca1a17244a1b25fce6bc66cd35aeba802f7ee435dab65ca54f1e96202530ab4f666a9fd9bfba4089b00a6"
	privBytes, _ := hex.DecodeString(testPrivKeyHex)
	sig := ed25519.Sign(privBytes, []byte(shaHex))
	sigHex := hex.EncodeToString(sig)

	// Write .sig file
	if err := os.WriteFile(binPath+".sig", []byte(sigHex), 0o644); err != nil {
		t.Fatal(err)
	}

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
						UpdateAvailable: true,
						LatestVersion:   version.Version,
					})
					server.serveAgentUpdate(session, "node1", binPath)
				}
			}(conn)
		}
	}()

	// Agent connects
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

	// Open update stream
	updateStream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer updateStream.Close()

	header, err := ReadUpdateHeader(updateStream)
	if err != nil {
		t.Fatal(err)
	}
	if header.Size != int64(len(dummyBinaryContent)) {
		t.Fatalf("expected size %d, got %d", len(dummyBinaryContent), header.Size)
	}
	if header.Signature != sigHex {
		t.Fatalf("expected signature %s, got %s", sigHex, header.Signature)
	}
}
