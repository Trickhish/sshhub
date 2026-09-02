// Package hubupdate handles automatic and CLI-driven updates for the SSHub Gateway and sshhub-ctl.
package hubupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Trickhish/sshhub/internal/release"
	"github.com/Trickhish/sshhub/internal/version"
)

const githubRepo = "Trickhish/sshhub"

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

var defaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:       5 * time.Second,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 100 * time.Millisecond,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          10,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: defaultTransport,
	}
}

// FetchLatestVersion queries GitHub for the latest release tag.
func FetchLatestVersion() (string, error) {
	// 1. Check direct release redirect header (instant, zero rate limits)
	latestURL := fmt.Sprintf("https://github.com/%s/releases/latest", githubRepo)
	req, err := http.NewRequest("GET", latestURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "sshhub-updater")
		checkClient := &http.Client{
			Timeout:   10 * time.Second,
			Transport: defaultTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if resp, err := checkClient.Do(req); err == nil {
			defer resp.Body.Close()
			if loc := resp.Header.Get("Location"); loc != "" {
				parts := strings.Split(loc, "/")
				if len(parts) > 0 {
					tag := parts[len(parts)-1]
					if tag != "" && tag != "latest" {
						return tag, nil
					}
				}
			}
		}
	}

	// 2. Fallback to GitHub API
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	client := newHTTPClient(10 * time.Second)
	req, err = http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sshhub-updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned HTTP %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release json: %w", err)
	}
	return rel.TagName, nil
}

// FetchLatestRelease returns the latest release's tag and publication time.
//
// Unlike FetchLatestVersion it always uses the GitHub API: the release redirect
// carries only the tag, and the publication time is what the update soak period
// is measured against.
func FetchLatestRelease() (tag string, publishedAt time.Time, err error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	client := newHTTPClient(10 * time.Second)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("User-Agent", "sshhub-updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("github API returned HTTP %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", time.Time{}, fmt.Errorf("decode release json: %w", err)
	}
	if rel.TagName == "" {
		return "", time.Time{}, fmt.Errorf("release has no tag")
	}
	return rel.TagName, rel.PublishedAt, nil
}

// IsNewer compares two semantic versions (e.g. "v0.3.0" > "0.2.0").
// IsNewer reports whether latest is strictly newer than current, comparing
// dotted numeric components (e.g. "0.10.0" > "0.9.1").
//
// It previously returned latest != current, which also reported true when
// latest was OLDER -- causing a downgrade to be advertised as an update.
func IsNewer(latest, current string) bool {
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	if latest == "" || current == "" {
		return false
	}
	return compareVersions(latest, current) > 0
}

// compareVersions returns >0 if a is newer than b, <0 if older, 0 if equal.
//
// Any pre-release suffix ("1.2.3-rc1") is ignored for ordering; only the
// numeric components are compared. Non-numeric components sort as 0, so a
// malformed version is never treated as newer than a valid one.
func compareVersions(a, b string) int {
	// Drop pre-release/build metadata.
	a = strings.SplitN(a, "-", 2)[0]
	b = strings.SplitN(b, "-", 2)[0]

	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

// DownloadAndApplyHubUpdate downloads the latest sshhub and sshhub-ctl release binaries
// from GitHub over verified HTTPS, replaces them in /usr/local/bin, and restarts the service.
func DownloadAndApplyHubUpdate(targetVersion string) error {
	arch := runtime.GOARCH
	goos := runtime.GOOS
	assetName := fmt.Sprintf("sshhub-%s-%s.tar.gz", goos, arch)

	tag := targetVersion
	if tag != "" && !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	installDir := "/usr/local/bin"
	if execPath, err := os.Executable(); err == nil {
		installDir = filepath.Dir(execPath)
	}

	client := newHTTPClient(3 * time.Minute)

	var downloadURL string
	if tag != "" {
		downloadURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", githubRepo, tag, assetName)
	} else {
		downloadURL = fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", githubRepo, assetName)
	}

	// Fetch and verify the signed manifest BEFORE downloading the artifact, so
	// an unsigned or untrusted release is refused without executing anything.
	manifest, err := fetchVerifiedManifest(client, tag)
	if err != nil {
		return err
	}

	log.Printf("hub: downloading update from %s...", downloadURL)
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sshhub-updater")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github HTTP %d for %s", resp.StatusCode, downloadURL)
	}

	// Buffer the artifact so its digest can be checked against the signed
	// manifest before a single byte is extracted to disk.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactBytes))
	if err != nil {
		return fmt.Errorf("read %s: %w", downloadURL, err)
	}
	if len(payload) == int(maxArtifactBytes) {
		return fmt.Errorf("release artifact exceeds %d bytes", maxArtifactBytes)
	}

	if manifest != nil {
		if err := release.VerifyArtifact(manifest, assetName, payload); err != nil {
			return fmt.Errorf("refusing update: %w", err)
		}
		log.Printf("hub: verified signature and digest for %s", assetName)
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("read gzip: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	tmpDir, err := os.MkdirTemp("", "sshhub-hub-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	binariesFound := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar archive: %w", err)
		}

		baseName := filepath.Base(header.Name)
		if header.Typeflag == tar.TypeReg && (baseName == "sshhub" || baseName == "sshhub-ctl") {
			tmpDst := filepath.Join(tmpDir, baseName)
			f, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
			if err != nil {
				return fmt.Errorf("create temp binary %s: %w", tmpDst, err)
			}
			if _, err := io.Copy(f, tarReader); err != nil {
				f.Close()
				return fmt.Errorf("extract %s: %w", baseName, err)
			}
			f.Close()
			binariesFound++
		}
	}

	if binariesFound == 0 {
		return fmt.Errorf("no binaries found in release archive")
	}

	// Atomically replace installed binaries
	for _, binName := range []string{"sshhub", "sshhub-ctl"} {
		src := filepath.Join(tmpDir, binName)
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(installDir, binName)
			if err := replaceBinary(src, dst); err != nil {
				return fmt.Errorf("replace %s: %w", dst, err)
			}
		}
	}

	log.Printf("hub: ✓ Successfully updated sshhub & sshhub-ctl in %s", installDir)
	return nil
}

func replaceBinary(src, dst string) error {
	_ = os.Chmod(src, 0o755)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Fallback copy
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// StartAutoUpdater runs a periodic background loop checking for GitHub releases.
// StartAutoUpdater periodically checks for a newer release and applies it.
//
// soak is how long a release must have been public before it is installed. It
// exists because the updater is the mechanism by which a bad release reaches
// production unattended: a release that breaks the control plane deploys
// itself, disconnects every agent, and (since the hub also fronts port 22) can
// remove the operator's own way back in. A soak period gives a broken release
// time to be noticed and replaced before it propagates.
//
// A soak of 0 means install as soon as a release is seen. A negative soak
// (Disabled) switches automatic updates off entirely: no polling goroutine is
// started, so the hub makes no outbound release requests at all.
func StartAutoUpdater(interval, soak time.Duration) {
	if soak < 0 {
		return
	}
	go func() {
		// Initial check 10 seconds after start
		time.Sleep(10 * time.Second)
		for {
			if applyIfDue(soak) {
				return
			}
			time.Sleep(interval)
		}
	}()
}

// updateChecker resolves the current latest release. Injectable for tests.
type updateChecker func(soak time.Duration) (tag string, publishedAt time.Time, err error)

// updateInstaller applies a release. Injectable for tests.
type updateInstaller func(tag string) error

func defaultChecker(soak time.Duration) (string, time.Time, error) {
	// With no soak period the tag alone is enough, so the cheap redirect path
	// is fine. Otherwise the publication time is required.
	if soak <= 0 {
		tag, err := FetchLatestVersion()
		return tag, time.Time{}, err
	}
	return FetchLatestRelease()
}

// applyIfDue performs one check. It reports whether an update was applied and
// the service is restarting.
//
// Each call re-resolves the CURRENT latest release rather than remembering the
// one that started the wait. So if a release turns out to be broken and is
// replaced during its soak period, the replacement is what eventually installs
// -- an emergency fix is picked up instead of the release it fixes.
func applyIfDue(soak time.Duration) bool {
	return applyIfDueWith(soak, defaultChecker, DownloadAndApplyHubUpdate, currentVersion)
}

// urgentLookup reports whether a release is marked urgent in its SIGNED
// manifest. Overridable in tests.
var urgentLookup = signedUrgentFromManifest

// signedUrgent reports whether the release carries a signature-verified urgent
// marker.
func signedUrgent(tag string) (bool, string) {
	return urgentLookup(tag)
}

func signedUrgentFromManifest(tag string) (bool, string) {
	m, err := LatestManifest(tag)
	if err != nil || m == nil {
		// Unverifiable means NOT urgent: an attacker who can serve a manifest but
		// not sign it must not be able to bypass the soak.
		return false, ""
	}
	if !m.Urgent {
		return false, ""
	}
	reason := m.UrgentReason
	if reason == "" {
		reason = "no reason given"
	}
	return true, reason
}

func currentVersion() string { return version.Version }

func applyIfDueWith(soak time.Duration, check updateChecker, install updateInstaller, current func() string) bool {
	// Guarded here as well as in StartAutoUpdater, so a future caller that
	// forgets the check cannot accidentally auto-update a hub whose operator
	// disabled it.
	if soak < 0 {
		return false
	}

	latest, published, err := check(soak)
	if err != nil {
		return false
	}

	if !IsNewer(latest, current()) {
		return false
	}

	if soak > 0 {
		// An urgent release may bypass the soak, but ONLY when the flag comes
		// from a signature-verified manifest. Otherwise anyone able to publish a
		// release could set it and defeat the operator's safety delay -- exactly
		// what the delay exists to prevent.
		urgent, reason := signedUrgent(latest)
		if urgent {
			log.Printf("hub: release %s is marked URGENT by the release signing key (%s); "+
				"bypassing the %s auto_update_wait", latest, reason, soak)
		} else {
			if published.IsZero() {
				// Fail closed: without a publication time the soak period cannot be
				// honoured, and installing anyway would silently defeat it.
				log.Printf("hub: release %s has no publication time; deferring update", latest)
				return false
			}
			if age := time.Since(published); age < soak {
				log.Printf("hub: release %s is %s old, waiting until it is %s old before updating",
					latest, age.Round(time.Minute), soak)
				return false
			}
		}
	}

	log.Printf("hub: new version %s detected (current %s). Performing automatic update...", latest, current())
	if err := install(latest); err != nil {
		log.Printf("hub: automatic update failed: %v", err)
		return false
	}

	log.Printf("hub: update applied. Restarting sshhub service...")
	_ = exec.Command("systemctl", "restart", "sshhub").Run()
	return true
}

// maxArtifactBytes bounds how much is buffered for digest verification, so a
// hostile or corrupted response cannot exhaust memory.
const maxArtifactBytes = 256 << 20 // 256 MiB

// manifestAssetName is the signed manifest published alongside the binaries.
const manifestAssetName = "sshhub-manifest.json"

// fetchVerifiedManifest downloads and verifies the release's signed manifest.
//
// It returns (nil, nil) when this build has no compiled-in signing key AND does
// not require one -- a locally built binary updating from a private build.
// Official builds set RequireSignature, so for them a missing or invalid
// manifest is a hard failure and the update is refused.
func fetchVerifiedManifest(client *http.Client, tag string) (*release.Manifest, error) {
	trusted, haveKey := release.TrustedKey()
	if !haveKey {
		if release.SignatureRequired() {
			return nil, fmt.Errorf("refusing update: this build requires signed releases " +
				"but has no trusted release key compiled in")
		}
		log.Printf("hub: WARNING: no release signing key compiled in; update will NOT be verified")
		return nil, nil
	}

	var url string
	if tag != "" {
		url = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", githubRepo, tag, manifestAssetName)
	} else {
		url = fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", githubRepo, manifestAssetName)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sshhub-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refusing update: cannot fetch release manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refusing update: release manifest unavailable (HTTP %d). "+
			"A release without a signed manifest cannot be verified", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("refusing update: read manifest: %w", err)
	}

	m, err := release.Verify(data, trusted)
	if err != nil {
		return nil, fmt.Errorf("refusing update: %w", err)
	}
	return m, nil
}

// LatestManifest returns the verified manifest for the latest release, or nil
// if this build cannot verify signatures. Used to consult the signed urgent
// flag before applying the operator's soak period.
func LatestManifest(tag string) (*release.Manifest, error) {
	return fetchVerifiedManifest(newHTTPClient(30*time.Second), tag)
}
