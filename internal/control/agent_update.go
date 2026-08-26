package control

import (
	"archive/tar"
	"compress/gzip"
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

// DownloadAndApplyGitHubUpdate downloads the latest release binary directly from GitHub
// over verified HTTPS, atomically replaces the local executable, and restarts the service.
func DownloadAndApplyGitHubUpdate(targetVersion string) error {
	arch := runtime.GOARCH
	goos := runtime.GOOS

	assetName := fmt.Sprintf("sshhub-agent-%s-%s.tar.gz", goos, arch)
	var downloadURL string
	if targetVersion != "" && !strings.HasPrefix(targetVersion, "0.0") {
		tag := targetVersion
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		downloadURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", githubRepo, tag, assetName)
	} else {
		downloadURL = fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", githubRepo, assetName)
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

	log.Printf("agent: downloading update from GitHub (%s)...", downloadURL)

	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("fetch %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		tmpFile.Close()
		rawBinaryURL := fmt.Sprintf("https://github.com/%s/releases/latest/download/sshhub-agent-%s-%s", githubRepo, goos, arch)
		return downloadRawBinary(rawBinaryURL, tmpPath, execPath)
	}

	if resp.StatusCode != http.StatusOK {
		tmpFile.Close()
		return fmt.Errorf("github returned HTTP %d for %s", resp.StatusCode, downloadURL)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		tmpFile.Close()
		return downloadRawBinary(downloadURL, tmpPath, execPath)
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
		return fmt.Errorf("sshhub-agent binary not found in GitHub release archive")
	}

	return installAndRestart(tmpPath, execPath)
}

func downloadRawBinary(url, tmpPath, execPath string) error {
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github HTTP %d for %s", resp.StatusCode, url)
	}

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return err
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
