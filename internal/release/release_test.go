package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testManifest() *Manifest {
	return &Manifest{
		SchemaVersion: ManifestVersion,
		Version:       "0.5.0",
		PublishedAt:   time.Now().UTC().Truncate(time.Second),
		Artifacts: map[string]string{
			"sshhub-linux-amd64.tar.gz": strings.Repeat("a", 64),
		},
	}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signed(t *testing.T, m *Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sm, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	m := testManifest()

	got, err := Verify(signed(t, m, priv), pub)
	if err != nil {
		t.Fatalf("a correctly signed manifest must verify: %v", err)
	}
	if got.Version != m.Version {
		t.Errorf("version = %q, want %q", got.Version, m.Version)
	}
}

// THE CORE PROPERTY: a manifest signed by any other key must be rejected. This
// is what stops someone who can publish a release from shipping code.
func TestVerify_WrongKeyRejected(t *testing.T) {
	_, attackerPriv := keypair(t)
	trustedPub, _ := keypair(t)

	if _, err := Verify(signed(t, testManifest(), attackerPriv), trustedPub); err == nil {
		t.Fatal("SECURITY: a manifest signed by an untrusted key was accepted")
	}
}

// Tampering with the manifest after signing must invalidate it.
func TestVerify_TamperedManifestRejected(t *testing.T) {
	pub, priv := keypair(t)
	data := signed(t, testManifest(), priv)

	var sm SignedManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		t.Fatal(err)
	}

	body, _ := base64.StdEncoding.DecodeString(sm.Manifest)
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	// Swap in an attacker-controlled digest.
	m.Artifacts["sshhub-linux-amd64.tar.gz"] = strings.Repeat("b", 64)
	tampered, _ := json.Marshal(&m)
	sm.Manifest = base64.StdEncoding.EncodeToString(tampered)

	out, _ := json.Marshal(sm)
	if _, err := Verify(out, pub); err == nil {
		t.Fatal("SECURITY: a manifest modified after signing was accepted")
	}
}

func TestVerify_MalformedInputsRejected(t *testing.T) {
	pub, _ := keypair(t)
	for name, data := range map[string][]byte{
		"empty":        {},
		"not json":     []byte("hello"),
		"empty object": []byte(`{}`),
		"missing sig":  []byte(`{"manifest":"eyJ9"}`),
		"bad base64":   []byte(`{"manifest":"!!!","signature":"!!!"}`),
		"null":         []byte(`null`),
	} {
		if _, err := Verify(data, pub); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// A manifest from a future schema must be refused rather than misinterpreted.
func TestVerify_UnknownSchemaRejected(t *testing.T) {
	pub, priv := keypair(t)
	m := testManifest()
	m.SchemaVersion = 99

	if _, err := Verify(signed(t, m, priv), pub); err == nil {
		t.Fatal("a future manifest schema must be rejected, not guessed at")
	}
}

func TestVerifyArtifact(t *testing.T) {
	payload := []byte("this is the release tarball")

	m := testManifest()
	// Correct digest for payload.
	m.Artifacts = map[string]string{"asset.tar.gz": sha256hex(payload)}

	if err := VerifyArtifact(m, "asset.tar.gz", payload); err != nil {
		t.Fatalf("matching artifact must verify: %v", err)
	}

	// SECURITY: substituted content must be caught.
	if err := VerifyArtifact(m, "asset.tar.gz", []byte("malicious payload")); err == nil {
		t.Fatal("SECURITY: an artifact whose digest does not match was accepted")
	}

	// An artifact absent from the manifest is not covered by the signature.
	if err := VerifyArtifact(m, "unlisted.tar.gz", payload); err == nil {
		t.Fatal("SECURITY: an artifact absent from the signed manifest was accepted")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := keypair(t)

	b64 := base64.StdEncoding.EncodeToString(pub)
	if got, err := ParsePublicKey(b64); err != nil || !got.Equal(pub) {
		t.Errorf("base64 key should parse: %v", err)
	}
	for _, bad := range []string{"", "not-a-key", "YWJj"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// The urgent flag must be inside the signed body, so it cannot be asserted by
// anyone who does not hold the signing key.
func TestUrgentFlagIsCoveredBySignature(t *testing.T) {
	pub, priv := keypair(t)
	m := testManifest()
	m.Urgent = false
	data := signed(t, m, priv)

	// An attacker flips urgent to true to bypass the operator's soak period.
	var sm SignedManifest
	json.Unmarshal(data, &sm)
	body, _ := base64.StdEncoding.DecodeString(sm.Manifest)
	var tampered Manifest
	json.Unmarshal(body, &tampered)
	tampered.Urgent = true
	tb, _ := json.Marshal(&tampered)
	sm.Manifest = base64.StdEncoding.EncodeToString(tb)
	out, _ := json.Marshal(sm)

	if _, err := Verify(out, pub); err == nil {
		t.Fatal("SECURITY: the urgent flag was modified without invalidating the signature")
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
