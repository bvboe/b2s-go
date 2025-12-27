package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// HTTPDownloader handles downloading release assets via direct HTTP
type HTTPDownloader struct {
	assetBaseURL string
	client       *http.Client
}

// NewHTTPDownloader creates a new HTTP downloader
func NewHTTPDownloader(assetBaseURL string) *HTTPDownloader {
	return &HTTPDownloader{
		assetBaseURL: assetBaseURL,
		client: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// DownloadAsset downloads a single asset from the constructed URL
func (hd *HTTPDownloader) DownloadAsset(ctx context.Context, version, filename, destPath string) error {
	// Construct URL: {baseURL}/{version}/{filename}
	url := fmt.Sprintf("%s/%s/%s", hd.assetBaseURL, version, filename)

	fmt.Printf("Downloading %s from %s...\n", filename, url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := hd.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = out.Close() }()

	// Copy response body to file
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// DownloadReleaseAssets downloads all required assets for a release
func (hd *HTTPDownloader) DownloadReleaseAssets(ctx context.Context, version, workDir string) (string, error) {
	// Determine asset names based on OS and architecture
	arch := runtime.GOARCH
	binaryName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz", arch)
	checksumName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sha256", arch)
	signatureName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sig", arch)
	certName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.cert", arch)

	// Download binary (required)
	binaryPath := filepath.Join(workDir, binaryName)
	if err := hd.DownloadAsset(ctx, version, binaryName, binaryPath); err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}

	// Download checksum (required)
	checksumPath := filepath.Join(workDir, checksumName)
	if err := hd.DownloadAsset(ctx, version, checksumName, checksumPath); err != nil {
		return "", fmt.Errorf("failed to download checksum: %w", err)
	}

	// Download signature (optional - may not exist)
	sigPath := filepath.Join(workDir, signatureName)
	if err := hd.DownloadAsset(ctx, version, signatureName, sigPath); err != nil {
		fmt.Printf("Note: Signature not available: %v\n", err)
		// Not fatal - signature is optional
	}

	// Download certificate (optional - may not exist)
	certPath := filepath.Join(workDir, certName)
	if err := hd.DownloadAsset(ctx, version, certName, certPath); err != nil {
		fmt.Printf("Note: Certificate not available: %v\n", err)
		// Not fatal - certificate is optional
	}

	return binaryPath, nil
}
