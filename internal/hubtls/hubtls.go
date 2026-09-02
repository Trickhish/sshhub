// Package hubtls manages the control plane's TLS identity.
//
// The control listener carries agent registration tokens, which are the agent's
// only credential. Before this it defaulted to plaintext TCP on a public port,
// so anyone on-path could read a token and register as that backend -- which
// also undermines the stream-header authorization model, since that assumes
// only the hub can write into a control session.
//
// The hub therefore always serves TLS. If the operator supplies a certificate
// it is used; otherwise a long-lived self-signed one is generated and persisted.
// Agents pin the certificate's public key fingerprint (SPKI SHA-256), so a
// self-signed certificate is not a weakness: pinning gives stronger guarantees
// than PKI here, because there is no CA that could be induced to issue for this
// name.
package hubtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Fingerprint returns the pin for a certificate: base64 SHA-256 of the
// SubjectPublicKeyInfo.
//
// SPKI is used rather than the whole certificate so the pin survives
// certificate renewal with the same key, matching HPKP/RFC 7469 practice.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// FingerprintFromPEM parses a PEM certificate and returns its pin.
func FingerprintFromPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	return Fingerprint(cert), nil
}

// LoadOrCreate returns the hub's TLS certificate, generating and persisting a
// self-signed one if certPath/keyPath do not yet exist.
//
// hosts are the names/IPs to place in the SAN. They matter only for clients
// doing hostname validation; pinning clients ignore them.
func LoadOrCreate(certPath, keyPath string, hosts []string) (tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("certificate and key paths are required")
	}

	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load keypair: %w", err)
		}
		return cert, nil
	}
	// Refuse a half-present pair rather than silently regenerating over one.
	if fileExists(certPath) != fileExists(keyPath) {
		return tls.Certificate{}, fmt.Errorf(
			"incomplete TLS keypair: exactly one of %s / %s exists; remove it to regenerate",
			certPath, keyPath)
	}

	certPEM, keyPEM, err := generateSelfSigned(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}

	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return tls.Certificate{}, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	// Private key must never be world-readable.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse generated keypair: %w", err)
	}
	return cert, nil
}

func generateSelfSigned(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sshhub control plane"},
		NotBefore:    time.Now().Add(-time.Hour),
		// Long-lived deliberately: agents pin the key, so rotation would force a
		// re-pin on every node for no security gain.
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// ServerConfig returns the hub's TLS server configuration.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// ClientConfig returns an agent's TLS configuration.
//
// When pin is non-empty the hub is authenticated by public key pin and normal
// chain/hostname verification is skipped -- appropriate for a self-signed hub,
// and strictly stronger than PKI for this purpose. When pin is empty the
// standard chain and hostname checks apply, for hubs using a CA-issued
// certificate.
func ClientConfig(serverName, pin string) (*tls.Config, error) {
	if pin == "" {
		return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
	}
	if _, err := parsePin(pin); err != nil {
		return nil, err
	}

	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		// Verification is performed by VerifyPeerCertificate below.
		InsecureSkipVerify: true, // #nosec G402 -- replaced by pin verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("hub presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse hub certificate: %w", err)
			}
			got := Fingerprint(cert)
			if !constantTimeEqual(got, pin) {
				return fmt.Errorf("hub key pin mismatch: expected %s, got %s "+
					"(the hub's key changed, or the connection is being intercepted)", pin, got)
			}
			return nil
		},
	}, nil
}

func parsePin(pin string) ([]byte, error) {
	const prefix = "sha256:"
	if len(pin) <= len(prefix) || pin[:len(prefix)] != prefix {
		return nil, fmt.Errorf("pin must start with %q", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(pin[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("pin is not valid base64: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("pin must be %d bytes, got %d", sha256.Size, len(raw))
	}
	return raw, nil
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
