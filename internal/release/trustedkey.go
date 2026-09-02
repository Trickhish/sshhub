package release

import (
	"crypto/ed25519"
	"os"
	"strings"
)

// TrustedPublicKey is the release signing key, injected at build time:
//
//	-ldflags "-X github.com/Trickhish/sshhub/internal/release.TrustedPublicKey=<base64>"
//
// It is empty in locally built binaries, which is why VerificationAvailable
// exists: a developer build should not silently behave as if it verifies.
var TrustedPublicKey = ""

// RequireSignature controls behaviour when no trusted key is compiled in.
//
// Injected as "true" for official release builds. When set, an update with no
// verifiable signature is refused rather than installed. Locally built binaries
// leave it unset so a developer can still update from a private build.
var RequireSignature = ""

// TrustedKey returns the compiled-in release signing key.
func TrustedKey() (ed25519.PublicKey, bool) {
	// An operator may pin a key out of band, e.g. when running a fork.
	if env := strings.TrimSpace(os.Getenv("SSHHUB_RELEASE_KEY")); env != "" {
		if k, err := ParsePublicKey(env); err == nil {
			return k, true
		}
	}
	if TrustedPublicKey == "" {
		return nil, false
	}
	k, err := ParsePublicKey(TrustedPublicKey)
	if err != nil {
		return nil, false
	}
	return k, true
}

// SignatureRequired reports whether an unverifiable update must be refused.
func SignatureRequired() bool {
	return strings.EqualFold(strings.TrimSpace(RequireSignature), "true")
}
