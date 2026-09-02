// Package release verifies the authenticity of downloaded release artifacts.
//
// # WHY THIS EXISTS
//
// The updater downloads a tarball from GitHub and executes its contents as
// root, on both the hub and every agent. Transport security (HTTPS) proves only
// that the bytes came from GitHub -- not that they were produced by the project
// maintainer. Anyone able to publish a release to the repository (a stolen
// token, a compromised CI workflow, a malicious dependency in the build) gets
// root on every installed hub and agent.
//
// Signing moves trust from "whoever can push a tag" to "whoever holds the
// release signing key", which is held offline by the maintainer and never
// present on the hub, on an agent, or in CI with write access to releases.
//
// # SCHEME
//
// Each release publishes a manifest listing every artifact and its SHA-256
// digest, plus a detached Ed25519 signature over the manifest bytes. Verifying
// one signature therefore covers every artifact, and the digest binds the
// downloaded bytes to the signed manifest.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ManifestVersion is the current manifest schema version.
const ManifestVersion = 1

// Manifest describes the contents of a release. It is the signed object.
type Manifest struct {
	SchemaVersion int `json:"schema_version"`

	// Version is the release tag, without a leading "v".
	Version string `json:"version"`

	// PublishedAt is when the release was built.
	PublishedAt time.Time `json:"published_at"`

	// Artifacts maps an asset filename to its lowercase hex SHA-256 digest.
	Artifacts map[string]string `json:"artifacts"`

	// Urgent marks a release that should bypass the operator's configured
	// auto_update_wait soak period.
	//
	// This is meaningful ONLY because it lives inside the signed manifest: it
	// asserts that the holder of the release signing key considers this release
	// critical. An equivalent flag carried in unsigned release metadata would
	// let anyone who can publish a release bypass the operator's safety delay,
	// which is precisely the risk the soak period exists to mitigate.
	Urgent bool `json:"urgent,omitempty"`

	// UrgentReason is shown to the operator in logs when Urgent is set, so a
	// bypassed soak is explainable after the fact.
	UrgentReason string `json:"urgent_reason,omitempty"`
}

// Bytes returns the canonical serialization that is signed and verified.
//
// Signing a canonical form rather than the transmitted bytes means the
// signature does not depend on key order or incidental whitespace, so a
// re-serialized manifest still verifies.
func (m *Manifest) Bytes() ([]byte, error) {
	// json.Marshal sorts map keys, so Artifacts is already deterministic; the
	// struct field order is fixed by its declaration.
	return json.Marshal(m)
}

// DigestFor returns the expected SHA-256 digest for an artifact.
func (m *Manifest) DigestFor(assetName string) (string, bool) {
	d, ok := m.Artifacts[assetName]
	return strings.ToLower(d), ok
}

// ArtifactNames lists the artifacts covered by the manifest, sorted.
func (m *Manifest) ArtifactNames() []string {
	names := make([]string, 0, len(m.Artifacts))
	for n := range m.Artifacts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SignedManifest is the manifest as published: the canonical bytes plus a
// detached signature over them.
type SignedManifest struct {
	// Manifest is the canonical JSON of the Manifest, base64 encoded.
	Manifest string `json:"manifest"`
	// Signature is the Ed25519 signature over the decoded manifest bytes,
	// base64 encoded.
	Signature string `json:"signature"`
}

// Sign produces a SignedManifest. Used by the release tooling, never on a hub
// or agent.
func Sign(m *Manifest, priv ed25519.PrivateKey) (*SignedManifest, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d", len(priv))
	}
	body, err := m.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize manifest: %w", err)
	}
	sig := ed25519.Sign(priv, body)
	return &SignedManifest{
		Manifest:  base64.StdEncoding.EncodeToString(body),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// ErrUntrusted reports a manifest that failed signature verification.
type ErrUntrusted struct{ Reason string }

func (e *ErrUntrusted) Error() string {
	return "release signature verification failed: " + e.Reason
}

// Verify checks a signed manifest against a trusted public key and returns the
// manifest it attests to.
//
// It fails closed on every error path: an unparsable, unsigned, or
// wrongly-signed manifest yields an error and never a usable Manifest.
func Verify(data []byte, pub ed25519.PublicKey) (*Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, &ErrUntrusted{Reason: fmt.Sprintf("invalid public key size %d", len(pub))}
	}

	var sm SignedManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, &ErrUntrusted{Reason: "manifest is not valid JSON: " + err.Error()}
	}
	if sm.Manifest == "" || sm.Signature == "" {
		return nil, &ErrUntrusted{Reason: "manifest or signature is missing"}
	}

	body, err := base64.StdEncoding.DecodeString(sm.Manifest)
	if err != nil {
		return nil, &ErrUntrusted{Reason: "manifest is not valid base64: " + err.Error()}
	}
	sig, err := base64.StdEncoding.DecodeString(sm.Signature)
	if err != nil {
		return nil, &ErrUntrusted{Reason: "signature is not valid base64: " + err.Error()}
	}

	if !ed25519.Verify(pub, body, sig) {
		return nil, &ErrUntrusted{Reason: "signature does not match the release signing key"}
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, &ErrUntrusted{Reason: "signed manifest is not valid JSON: " + err.Error()}
	}
	if m.SchemaVersion != ManifestVersion {
		return nil, &ErrUntrusted{Reason: fmt.Sprintf(
			"unsupported manifest schema %d (this build understands %d)", m.SchemaVersion, ManifestVersion)}
	}
	if len(m.Artifacts) == 0 {
		return nil, &ErrUntrusted{Reason: "manifest covers no artifacts"}
	}
	return &m, nil
}

// VerifyArtifact checks downloaded bytes against the digest in a verified
// manifest.
func VerifyArtifact(m *Manifest, assetName string, data []byte) error {
	want, ok := m.DigestFor(assetName)
	if !ok {
		return &ErrUntrusted{Reason: fmt.Sprintf(
			"artifact %q is not covered by the signed manifest", assetName)}
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return &ErrUntrusted{Reason: fmt.Sprintf(
			"artifact %q digest mismatch: expected %s, got %s", assetName, want, got)}
	}
	return nil
}

// ParsePublicKey decodes a base64 or hex encoded Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty public key")
	}

	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("public key must be %d bytes, base64 or hex encoded", ed25519.PublicKeySize)
}
