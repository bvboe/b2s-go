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
	assetBaseURL     string
	client           *http.Client
	maxRetries       int
	enableValidation bool
}

// NewHTTPDownloader creates a new HTTP downloader
func NewHTTPDownloader(assetBaseURL string) *HTTPDownloader {
	return &HTTPDownloader{
		assetBaseURL:     assetBaseURL,
		maxRetries:       3,
		enableValidation: true,
		client: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// SetMaxRetries sets the maximum number of download retries
func (hd *HTTPDownloader) SetMaxRetries(retries int) {
	hd.maxRetries = retries
}

// SetValidation enables or disables pre-flight validation
func (hd *HTTPDownloader) SetValidation(enabled bool) {
	hd.enableValidation = enabled
}

// ValidateAssetAvailability checks if an asset exists using a HEAD request
func (hd *HTTPDownloader) ValidateAssetAvailability(ctx context.Context, version, filename string) error {
	url := fmt.Sprintf("%s/%s/%s", hd.assetBaseURL, version, filename)

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HEAD request: %w", err)
	}

	resp, err := hd.client.Do(req)
	if err != nil {
		return fmt.Errorf("HEAD request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asset not available (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(statusCode int, err error) bool {
	// Retry on network errors
	if err != nil {
		return true
	}

	// Retry on temporary server errors
	if statusCode == http.StatusServiceUnavailable || // 503
		statusCode == http.StatusGatewayTimeout || // 504
		statusCode == http.StatusTooManyRequests || // 429
		statusCode == http.StatusRequestTimeout { // 408
		return true
	}

	// Don't retry on client errors (404, 403, etc.)
	return false
}

// DownloadAsset downloads a single asset from the constructed URL
func (hd *HTTPDownloader) DownloadAsset(ctx context.Context, version, filename, destPath string) error {
	url := fmt.Sprintf("%s/%s/%s", hd.assetBaseURL, version, filename)

	// Validate asset availability first if enabled
	if hd.enableValidation {
		if err := hd.ValidateAssetAvailability(ctx, version, filename); err != nil {
			return fmt.Errorf("pre-flight validation failed: %w", err)
		}
	}

	// Attempt download with retries
	var lastErr error
	var lastStatusCode int

	for attempt := 0; attempt <= hd.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s, 16s, max 30s
			backoff := time.Duration(1<<uint(attempt-1)) * 2 * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}

			fmt.Printf("Retry attempt %d/%d for %s after %v...\n", attempt, hd.maxRetries, filename, backoff)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Attempt download
		err := hd.downloadAssetOnce(ctx, url, filename, destPath)
		if err == nil {
			if attempt > 0 {
				fmt.Printf("Download succeeded on retry attempt %d\n", attempt)
			}
			return nil // Success
		}

		lastErr = err
		lastStatusCode = hd.extractStatusCode(err)

		// Check if error is retryable
		if !isRetryableError(lastStatusCode, err) {
			return fmt.Errorf("download failed (non-retryable): %w", err)
		}
	}

	return fmt.Errorf("download failed after %d retries: %w", hd.maxRetries, lastErr)
}

// downloadAssetOnce performs a single download attempt
func (hd *HTTPDownloader) downloadAssetOnce(ctx context.Context, url, filename, destPath string) error {
	if filename != "" {
		fmt.Printf("Downloading %s from %s...\n", filename, url)
	}

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

// extractStatusCode attempts to extract HTTP status code from error
func (hd *HTTPDownloader) extractStatusCode(err error) int {
	if err == nil {
		return 0
	}
	// Simple parsing - look for "status XXX" in error message
	errStr := err.Error()
	if len(errStr) > 20 {
		// Check for "status XXX" pattern
		if idx := len(errStr) - 3; idx > 0 {
			if errStr[idx-7:idx] == "status " {
				var code int
				if _, parseErr := fmt.Sscanf(errStr[idx:], "%d", &code); parseErr == nil {
					return code
				}
			}
		}
	}
	return 0
}

// DownloadReleaseAssets downloads all required assets for a release
func (hd *HTTPDownloader) DownloadReleaseAssets(ctx context.Context, version, workDir string) (string, error) {
	// Determine asset names based on OS and architecture
	arch := runtime.GOARCH
	binaryName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz", arch)
	checksumName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sha256", arch)
	signatureName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sig", arch)
	certName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.cert", arch)

	// Validate all required assets are available before downloading
	if hd.enableValidation {
		fmt.Println("Validating release asset availability...")
		requiredAssets := []string{binaryName, checksumName}

		for _, asset := range requiredAssets {
			if err := hd.ValidateAssetAvailability(ctx, version, asset); err != nil {
				return "", fmt.Errorf("required asset %s not available: %w", asset, err)
			}
		}
		fmt.Println("All required assets available ✓")
	}

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
