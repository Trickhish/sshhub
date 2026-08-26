// Package hubupdate handles automatic and CLI-driven updates for the SSHub Gateway and sshhub-ctl.
package hubupdate

import (
	"archive/tar"
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
	"strings"
	"time"

	"github.com/Trickhish/sshhub/internal/version"
)

const githubRepo = "Trickhish/sshhub"

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:       5 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 100 * time.Millisecond, // fast Happy Eyeballs IPv4 fallback
			}).DialContext,
		},
	}
}

// FetchLatestVersion queries GitHub for the latest release tag.
func FetchLatestVersion() (string, error) {
	client := newHTTPClient(10 * time.Second)

	// 1. Check direct release redirect header (instant, zero rate limits)
	latestURL := fmt.Sprintf("https://github.com/%s/releases/latest", githubRepo)
	req, err := http.NewRequest("HEAD", latestURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "sshhub-updater")
		checkClient := &http.Client{
			Timeout:   10 * time.Second,
			Transport: client.Transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if resp, err := checkClient.Do(req); err == nil {
			resp.Body.Close()
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

// IsNewer compares two semantic versions (e.g. "v0.3.0" > "0.2.0").
func IsNewer(latest, current string) bool {
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	if latest == "" || current == "" {
		return false
	}
	return latest != current
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

	// 1. Try GitHub API for direct asset download
	var apiURL string
	if tag != "" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", githubRepo, tag)
	} else {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	}

	var body io.ReadCloser
	req, err := http.NewRequest("GET", apiURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "sshhub-updater")
		if resp, err := client.Do(req); err == nil && resp.StatusCode == http.StatusOK {
			var rel githubRelease
			if err := json.NewDecoder(resp.Body).Decode(&rel); err == nil {
				for _, asset := range rel.Assets {
					if asset.Name == assetName && asset.URL != "" {
						assetReq, err := http.NewRequest("GET", asset.URL, nil)
						if err == nil {
							assetReq.Header.Set("Accept", "application/octet-stream")
							assetReq.Header.Set("User-Agent", "sshhub-updater")
							if assetResp, err := client.Do(assetReq); err == nil && assetResp.StatusCode == http.StatusOK {
								body = assetResp.Body
								log.Printf("hub: downloading update via GitHub API (%s)...", asset.Name)
								break
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
	}

	// 2. Fallback to direct browser download URL
	if body == nil {
		var downloadURL string
		if tag != "" {
			downloadURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", githubRepo, tag, assetName)
		} else {
			downloadURL = fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", githubRepo, assetName)
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
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("github HTTP %d for %s", resp.StatusCode, downloadURL)
		}
		body = resp.Body
	}
	defer body.Close()

	gzReader, err := gzip.NewReader(body)
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
func StartAutoUpdater(interval time.Duration) {
	go func() {
		// Initial check 10 seconds after start
		time.Sleep(10 * time.Second)
		for {
			if latest, err := FetchLatestVersion(); err == nil {
				if IsNewer(latest, version.Version) {
					log.Printf("hub: new version %s detected (current %s). Performing automatic update...", latest, version.Version)
					if err := DownloadAndApplyHubUpdate(latest); err == nil {
						log.Printf("hub: update applied. Restarting sshhub service...")
						_ = exec.Command("systemctl", "restart", "sshhub").Run()
						return
					} else {
						log.Printf("hub: automatic update failed: %v", err)
					}
				}
			}
			time.Sleep(interval)
		}
	}()
}
