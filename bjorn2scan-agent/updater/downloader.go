package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-github/v57/github"
)

// Downloader handles downloading and verifying release assets
type Downloader struct {
	githubClient *GitHubClient
	workDir      string
}

// NewDownloader creates a new downloader
func NewDownloader(githubClient *GitHubClient) (*Downloader, error) {
	// Create temporary work directory
	workDir, err := os.MkdirTemp("", "bjorn2scan-update-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	return &Downloader{
		githubClient: githubClient,
		workDir:      workDir,
	}, nil
}

// DownloadRelease downloads the binary, checksum, signature, and certificate for a release
func (d *Downloader) DownloadRelease(ctx context.Context, release *github.RepositoryRelease) (string, error) {
	// Determine asset names based on OS and architecture
	arch := runtime.GOARCH
	binaryName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz", arch)
	checksumName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sha256", arch)
	signatureName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sig", arch)
	certName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.cert", arch)

	// Find assets
	binaryAsset := d.githubClient.FindAssetByName(release, binaryName)
	checksumAsset := d.githubClient.FindAssetByName(release, checksumName)
	sigAsset := d.githubClient.FindAssetByName(release, signatureName)
	certAsset := d.githubClient.FindAssetByName(release, certName)

	if binaryAsset == nil {
		return "", fmt.Errorf("binary asset %s not found in release", binaryName)
	}
	if checksumAsset == nil {
		return "", fmt.Errorf("checksum asset %s not found in release", checksumName)
	}

	// Download binary
	binaryPath := filepath.Join(d.workDir, binaryName)
	fmt.Printf("Downloading %s...\n", binaryName)
	if err := d.githubClient.DownloadAsset(ctx, binaryAsset.GetID(), binaryPath); err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}

	// Download checksum
	checksumPath := filepath.Join(d.workDir, checksumName)
	fmt.Printf("Downloading %s...\n", checksumName)
	if err := d.githubClient.DownloadAsset(ctx, checksumAsset.GetID(), checksumPath); err != nil {
		return "", fmt.Errorf("failed to download checksum: %w", err)
	}

	// Verify checksum
	fmt.Println("Verifying checksum...")
	if err := d.VerifyChecksum(binaryPath, checksumPath); err != nil {
		return "", fmt.Errorf("checksum verification failed: %w", err)
	}
	fmt.Println("Checksum verified ✓")

	// Download signature if available
	if sigAsset != nil {
		sigPath := filepath.Join(d.workDir, signatureName)
		fmt.Printf("Downloading %s...\n", signatureName)
		if err := d.githubClient.DownloadAsset(ctx, sigAsset.GetID(), sigPath); err != nil {
			return "", fmt.Errorf("failed to download signature: %w", err)
		}
	}

	// Download certificate if available
	if certAsset != nil {
		certPath := filepath.Join(d.workDir, certName)
		fmt.Printf("Downloading %s...\n", certName)
		if err := d.githubClient.DownloadAsset(ctx, certAsset.GetID(), certPath); err != nil {
			return "", fmt.Errorf("failed to download certificate: %w", err)
		}
	}

	return binaryPath, nil
}

// VerifyChecksum verifies the SHA256 checksum of a file
func (d *Downloader) VerifyChecksum(filePath, checksumPath string) error {
	// Read expected checksum
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Parse checksum (format: "hash  filename")
	parts := strings.Fields(string(checksumData))
	if len(parts) < 1 {
		return fmt.Errorf("invalid checksum file format")
	}
	expectedChecksum := parts[0]

	// Calculate actual checksum
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// Compare checksums
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// ExtractBinary extracts the binary from the tarball
func (d *Downloader) ExtractBinary(tarballPath string) (string, error) {
	file, err := os.Open(tarballPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tarball: %w", err)
	}
	defer func() { _ = file.Close() }()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)

	// Find and extract the binary
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// Look for the binary (should be named bjorn2scan-agent)
		if filepath.Base(header.Name) == "bjorn2scan-agent" {
			extractPath := filepath.Join(d.workDir, "bjorn2scan-agent")
			out, err := os.OpenFile(extractPath, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create extracted file: %w", err)
			}
			defer func() { _ = out.Close() }()

			if _, err := io.Copy(out, tr); err != nil {
				return "", fmt.Errorf("failed to extract binary: %w", err)
			}

			return extractPath, nil
		}
	}

	return "", fmt.Errorf("binary not found in tarball")
}

// Cleanup removes the work directory
func (d *Downloader) Cleanup() error {
	if d.workDir != "" {
		return os.RemoveAll(d.workDir)
	}
	return nil
}

// GetWorkDir returns the work directory path
func (d *Downloader) GetWorkDir() string {
	return d.workDir
}
