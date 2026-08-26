package control

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
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

// DownloadAndApplyGitHubUpdate downloads the latest release binary directly from GitHub
// over verified HTTPS, atomically replaces the local executable, and restarts the service.
func DownloadAndApplyGitHubUpdate(targetVersion string) error {
	arch := runtime.GOARCH
	goos := runtime.GOOS
	assetName := fmt.Sprintf("sshhub-agent-%s-%s.tar.gz", goos, arch)

	tag := targetVersion
	if tag != "" && !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/sshhub-agent"
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		execPath = "/usr/local/bin/sshhub-agent"
	}

	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, "sshhub-agent-update-*")
	if err != nil {
		tmpFile, err = os.CreateTemp("/tmp", "sshhub-agent-update-*")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	client := &http.Client{Timeout: 3 * time.Minute}

	// 1. Try fetching release asset metadata via GitHub API first
	var apiURL string
	if tag != "" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", githubRepo, tag)
	} else {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	}

	var body io.ReadCloser
	req, err := http.NewRequest("GET", apiURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "sshhub-agent-updater")
		if resp, err := client.Do(req); err == nil && resp.StatusCode == http.StatusOK {
			var rel githubRelease
			if err := json.NewDecoder(resp.Body).Decode(&rel); err == nil {
				for _, asset := range rel.Assets {
					if asset.Name == assetName && asset.URL != "" {
						assetReq, err := http.NewRequest("GET", asset.URL, nil)
						if err == nil {
							assetReq.Header.Set("Accept", "application/octet-stream")
							assetReq.Header.Set("User-Agent", "sshhub-agent-updater")
							if assetResp, err := client.Do(assetReq); err == nil && assetResp.StatusCode == http.StatusOK {
								body = assetResp.Body
								log.Printf("agent: downloading update via GitHub API (%s)...", asset.Name)
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
		log.Printf("agent: downloading update from %s...", downloadURL)
		req, err := http.NewRequest("GET", downloadURL, nil)
		if err != nil {
			tmpFile.Close()
			return err
		}
		req.Header.Set("User-Agent", "sshhub-agent-updater")
		resp, err := client.Do(req)
		if err != nil {
			tmpFile.Close()
			return fmt.Errorf("fetch %s: %w", downloadURL, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			tmpFile.Close()
			return fmt.Errorf("github HTTP %d for %s", resp.StatusCode, downloadURL)
		}
		body = resp.Body
	}
	defer body.Close()

	gzReader, err := gzip.NewReader(body)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("read gzip: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	found := false
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			tmpFile.Close()
			return fmt.Errorf("read tar archive: %w", err)
		}

		if header.Typeflag == tar.TypeReg && (header.Name == "sshhub-agent" || strings.HasSuffix(header.Name, "/sshhub-agent")) {
			if _, err := io.Copy(tmpFile, tarReader); err != nil {
				tmpFile.Close()
				return fmt.Errorf("extract binary from archive: %w", err)
			}
			found = true
			break
		}
	}
	tmpFile.Close()

	if !found {
		return fmt.Errorf("sshhub-agent binary not found in release archive")
	}

	return installAndRestart(tmpPath, execPath)
}

func installAndRestart(tmpPath, execPath string) error {
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod binary: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		if err := copyFile(tmpPath, execPath); err != nil {
			return fmt.Errorf("replace executable %s: %w", execPath, err)
		}
	}

	log.Printf("agent: ✓ Successfully updated sshhub-agent from GitHub to %s! Restarting...", execPath)

	if err := exec.Command("systemctl", "restart", "sshhub-agent").Start(); err == nil {
		os.Exit(0)
	}

	return syscall.Exec(execPath, os.Args, os.Environ())
}

func copyFile(src, dst string) error {
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
