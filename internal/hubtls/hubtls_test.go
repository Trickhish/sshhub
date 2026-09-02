package hubtls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	dir := t.TempDir()
	cert, err := LoadOrCreate(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return cert, Fingerprint(leaf)
}

// serve starts a TLS echo server and returns its address.
func serve(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ServerConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := c.Read(buf); err == nil {
					c.Write(buf)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func dial(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Handshake()
}

func TestCorrectPinConnects(t *testing.T) {
	cert, pin := testCert(t)
	addr := serve(t, cert)

	cfg, err := ClientConfig("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := dial(t, addr, cfg); err != nil {
		t.Fatalf("correct pin should connect: %v", err)
	}
}

// The security-critical case: a different hub key must be refused. This is what
// stops an on-path attacker from impersonating the hub and harvesting tokens.
func TestWrongPinRefused(t *testing.T) {
	// The impostor serves a valid certificate -- just not the pinned one.
	impostorCert, _ := testCert(t)
	_, realPin := testCert(t)
	addr := serve(t, impostorCert)

	cfg, err := ClientConfig("127.0.0.1", realPin)
	if err != nil {
		t.Fatal(err)
	}
	err = dial(t, addr, cfg)
	if err == nil {
		t.Fatal("SECURITY: connected to a hub whose key does not match the pin")
	}
	if !strings.Contains(err.Error(), "pin mismatch") {
		t.Errorf("error should identify a pin mismatch, got: %v", err)
	}
}

func TestMalformedPinRejectedEarly(t *testing.T) {
	for _, bad := range []string{
		"not-a-pin",
		"sha256:",
		"sha256:!!!!",
		"sha256:c2hvcnQ=", // valid base64, wrong length
		"md5:abcd",
	} {
		if _, err := ClientConfig("h", bad); err == nil {
			t.Errorf("malformed pin %q must be rejected", bad)
		}
	}
}

// The pin must be stable across restarts, or every hub restart would lock out
// every agent.
func TestPinStableAcrossReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	c1, err := LoadOrCreate(certPath, keyPath, []string{"h"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreate(certPath, keyPath, []string{"h"})
	if err != nil {
		t.Fatal(err)
	}

	l1, _ := x509.ParseCertificate(c1.Certificate[0])
	l2, _ := x509.ParseCertificate(c2.Certificate[0])
	if Fingerprint(l1) != Fingerprint(l2) {
		t.Fatal("pin changed on reload; every agent would be locked out on hub restart")
	}
}

func TestGeneratedKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.pem")
	if _, err := LoadOrCreate(filepath.Join(dir, "c.pem"), keyPath, []string{"h"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("private key is group/world accessible: %04o", perm)
	}
}

// A half-present keypair must be an error, not a silent regeneration that would
// change the pin and lock out agents.
func TestIncompleteKeypairRefused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	if _, err := LoadOrCreate(certPath, keyPath, []string{"h"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(certPath, keyPath, []string{"h"}); err == nil {
		t.Fatal("a half-present keypair must be refused, not silently regenerated")
	}
}

func TestFingerprintFromPEMMatches(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	cert, err := LoadOrCreate(certPath, filepath.Join(dir, "k.pem"), []string{"h"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FingerprintFromPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != Fingerprint(leaf) {
		t.Fatalf("pin from PEM %q != pin from cert %q", got, Fingerprint(leaf))
	}
}

// TLS 1.0/1.1 must not be negotiable.
func TestMinimumTLSVersion(t *testing.T) {
	cert, pin := testCert(t)
	addr := serve(t, cert)

	cfg, err := ClientConfig("127.0.0.1", pin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxVersion = tls.VersionTLS11
	if err := dial(t, addr, cfg); err == nil {
		t.Fatal("server accepted TLS < 1.2")
	}
}
