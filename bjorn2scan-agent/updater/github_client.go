package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v57/github"
)

// GitHubClient handles GitHub API interactions
type GitHubClient struct {
	client *github.Client
	owner  string
	repo   string
}

// NewGitHubClient creates a new GitHub client
func NewGitHubClient(repoPath string) (*GitHubClient, error) {
	// Parse "owner/repo" format
	parts := strings.Split(repoPath, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo path %s, expected format: owner/repo", repoPath)
	}

	client := github.NewClient(nil)

	return &GitHubClient{
		client: client,
		owner:  parts[0],
		repo:   parts[1],
	}, nil
}

// GetLatestRelease returns the latest release
func (gc *GitHubClient) GetLatestRelease(ctx context.Context) (*github.RepositoryRelease, error) {
	release, _, err := gc.client.Repositories.GetLatestRelease(ctx, gc.owner, gc.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest release: %w", err)
	}

	return release, nil
}

// ListReleases lists all releases
func (gc *GitHubClient) ListReleases(ctx context.Context) ([]*github.RepositoryRelease, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}

	releases, _, err := gc.client.Repositories.ListReleases(ctx, gc.owner, gc.repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list releases: %w", err)
	}

	return releases, nil
}

// DownloadAsset downloads a release asset to the specified path
func (gc *GitHubClient) DownloadAsset(ctx context.Context, assetID int64, destPath string) error {
	// Get asset
	asset, redirectURL, err := gc.client.Repositories.DownloadReleaseAsset(ctx, gc.owner, gc.repo, assetID, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("failed to download asset: %w", err)
	}

	// If we got a redirect URL, download from there
	if redirectURL != "" {
		return gc.downloadFromURL(ctx, redirectURL, destPath)
	}

	// Otherwise read from the reader
	if asset == nil {
		return fmt.Errorf("no asset content returned")
	}
	defer func() { _ = asset.Close() }()

	return gc.writeToFile(asset, destPath)
}

// FindAssetByName finds an asset by name in a release
func (gc *GitHubClient) FindAssetByName(release *github.RepositoryRelease, name string) *github.ReleaseAsset {
	for _, asset := range release.Assets {
		if asset.GetName() == name {
			return asset
		}
	}
	return nil
}

// downloadFromURL downloads content from a URL
func (gc *GitHubClient) downloadFromURL(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	return gc.writeToFile(resp.Body, destPath)
}

// writeToFile writes content from reader to file
func (gc *GitHubClient) writeToFile(reader io.Reader, destPath string) error {
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, reader); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
