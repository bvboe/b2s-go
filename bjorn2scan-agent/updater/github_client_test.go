package updater

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v57/github"
)

func TestNewGitHubClient(t *testing.T) {
	tests := []struct {
		name      string
		repoPath  string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "Valid repo path",
			repoPath:  "bvboe/b2s-go",
			wantOwner: "bvboe",
			wantRepo:  "b2s-go",
			wantErr:   false,
		},
		{
			name:      "Another valid repo path",
			repoPath:  "kubernetes/kubernetes",
			wantOwner: "kubernetes",
			wantRepo:  "kubernetes",
			wantErr:   false,
		},
		{
			name:     "Invalid repo path - too many parts",
			repoPath: "owner/repo/extra",
			wantErr:  true,
		},
		{
			name:     "Invalid repo path - too few parts",
			repoPath: "single",
			wantErr:  true,
		},
		{
			name:     "Invalid repo path - empty",
			repoPath: "",
			wantErr:  true,
		},
		{
			name:      "Repo path with only slash",
			repoPath:  "/",
			wantOwner: "",
			wantRepo:  "",
			wantErr:   false, // splits to ["", ""] which has 2 parts
		},
		{
			name:      "Repo path with trailing slash",
			repoPath:  "owner/repo/",
			wantOwner: "",
			wantRepo:  "",
			wantErr:   true, // Will have 3 parts: "owner", "repo", ""
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewGitHubClient(tt.repoPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewGitHubClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if client != nil {
					t.Error("NewGitHubClient() returned client when error expected")
				}
				if err == nil {
					t.Error("NewGitHubClient() returned nil error when error expected")
				}
				if err != nil && !strings.Contains(err.Error(), "invalid repo path") {
					t.Errorf("Error message = %q, want error containing 'invalid repo path'", err.Error())
				}
				return
			}

			if client == nil {
				t.Fatal("NewGitHubClient() returned nil client")
				return
			}

			if client.owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", client.owner, tt.wantOwner)
			}

			if client.repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", client.repo, tt.wantRepo)
			}

			if client.client == nil {
				t.Error("GitHub API client is nil")
			}
		})
	}
}

func TestGitHubClient_FindAssetByName(t *testing.T) {
	// Helper to create test release assets
	createAsset := func(name string, id int64) *github.ReleaseAsset {
		return &github.ReleaseAsset{
			ID:   github.Int64(id),
			Name: github.String(name),
		}
	}

	tests := []struct {
		name        string
		assets      []*github.ReleaseAsset
		searchName  string
		wantAssetID *int64
	}{
		{
			name: "Find existing asset",
			assets: []*github.ReleaseAsset{
				createAsset("file1.tar.gz", 1),
				createAsset("file2.tar.gz", 2),
				createAsset("checksums.txt", 3),
			},
			searchName:  "file2.tar.gz",
			wantAssetID: github.Int64(2),
		},
		{
			name: "Asset not found",
			assets: []*github.ReleaseAsset{
				createAsset("file1.tar.gz", 1),
				createAsset("file2.tar.gz", 2),
			},
			searchName:  "nonexistent.tar.gz",
			wantAssetID: nil,
		},
		{
			name:        "Empty assets list",
			assets:      []*github.ReleaseAsset{},
			searchName:  "file.tar.gz",
			wantAssetID: nil,
		},
		{
			name:        "Nil assets list",
			assets:      nil,
			searchName:  "file.tar.gz",
			wantAssetID: nil,
		},
		{
			name: "Find first match when duplicates exist",
			assets: []*github.ReleaseAsset{
				createAsset("duplicate.tar.gz", 1),
				createAsset("duplicate.tar.gz", 2),
			},
			searchName:  "duplicate.tar.gz",
			wantAssetID: github.Int64(1),
		},
		{
			name: "Case sensitive search",
			assets: []*github.ReleaseAsset{
				createAsset("File.tar.gz", 1),
				createAsset("file.tar.gz", 2),
			},
			searchName:  "file.tar.gz",
			wantAssetID: github.Int64(2),
		},
	}

	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := &github.RepositoryRelease{
				Assets: tt.assets,
			}

			asset := client.FindAssetByName(release, tt.searchName)

			if tt.wantAssetID == nil {
				if asset != nil {
					t.Errorf("FindAssetByName() returned asset %v, want nil", asset)
				}
				return
			}

			if asset == nil {
				t.Fatal("FindAssetByName() returned nil, want asset")
			}

			if asset.GetID() != *tt.wantAssetID {
				t.Errorf("Asset ID = %d, want %d", asset.GetID(), *tt.wantAssetID)
			}
		})
	}
}

func TestGitHubClient_WriteToFile(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "Write simple content",
			content: "test content",
			wantErr: false,
		},
		{
			name:    "Write empty content",
			content: "",
			wantErr: false,
		},
		{
			name:    "Write large content",
			content: strings.Repeat("x", 10000),
			wantErr: false,
		},
		{
			name:    "Write binary content",
			content: "\x00\x01\x02\x03\xff\xfe",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			destPath := filepath.Join(tmpDir, "output")

			reader := strings.NewReader(tt.content)
			err := client.writeToFile(reader, destPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("writeToFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify file was written
			written, err := os.ReadFile(destPath)
			if err != nil {
				t.Fatalf("Failed to read written file: %v", err)
			}

			if string(written) != tt.content {
				t.Errorf("Written content = %q, want %q", string(written), tt.content)
			}
		})
	}
}

func TestGitHubClient_WriteToFile_InvalidPath(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	// Try to write to invalid path
	reader := strings.NewReader("test")
	err = client.writeToFile(reader, "/nonexistent/directory/file")
	if err == nil {
		t.Fatal("writeToFile() expected error for invalid path, got nil")
	}

	if !strings.Contains(err.Error(), "failed to create file") {
		t.Errorf("Error = %v, want error containing 'failed to create file'", err)
	}
}

func TestGitHubClient_WriteToFile_ReadError(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "output")

	// Create reader that returns error
	reader := &errorReader{err: io.ErrUnexpectedEOF}
	err = client.writeToFile(reader, destPath)

	if err == nil {
		t.Fatal("writeToFile() expected error from reader, got nil")
	}

	if !strings.Contains(err.Error(), "failed to write file") {
		t.Errorf("Error = %v, want error containing 'failed to write file'", err)
	}
}

func TestGitHubClient_DownloadFromURL(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	tests := []struct {
		name         string
		content      string
		statusCode   int
		wantErr      bool
		errContains  string
	}{
		{
			name:       "Successful download",
			content:    "file content",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:        "Not found",
			content:     "",
			statusCode:  http.StatusNotFound,
			wantErr:     true,
			errContains: "download failed with status 404",
		},
		{
			name:        "Server error",
			content:     "",
			statusCode:  http.StatusInternalServerError,
			wantErr:     true,
			errContains: "download failed with status 500",
		},
		{
			name:       "Large file",
			content:    strings.Repeat("x", 100000),
			statusCode: http.StatusOK,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					_, _ = w.Write([]byte(tt.content))
				}
			}))
			defer server.Close()

			tmpDir := t.TempDir()
			destPath := filepath.Join(tmpDir, "download")

			ctx := context.Background()
			err := client.downloadFromURL(ctx, server.URL, destPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("downloadFromURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify downloaded content
			downloaded, err := os.ReadFile(destPath)
			if err != nil {
				t.Fatalf("Failed to read downloaded file: %v", err)
			}

			if string(downloaded) != tt.content {
				t.Errorf("Downloaded content length = %d, want %d", len(downloaded), len(tt.content))
			}
		})
	}
}

func TestGitHubClient_DownloadFromURL_InvalidURL(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "download")

	ctx := context.Background()
	err = client.downloadFromURL(ctx, "http://127.0.0.1:1", destPath)

	if err == nil {
		t.Fatal("downloadFromURL() expected error for unreachable URL, got nil")
	}

	if !strings.Contains(err.Error(), "failed to download") {
		t.Errorf("Error = %v, want error containing 'failed to download'", err)
	}
}

func TestGitHubClient_DownloadFromURL_ContextCancellation(t *testing.T) {
	client, err := NewGitHubClient("owner/repo")
	if err != nil {
		t.Fatalf("Failed to create GitHub client: %v", err)
	}

	// Create server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context was cancelled
		select {
		case <-r.Context().Done():
			return
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "download")

	// Create context and cancel it immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = client.downloadFromURL(ctx, server.URL, destPath)

	if err == nil {
		t.Fatal("downloadFromURL() expected error for cancelled context, got nil")
	}
}

// errorReader is a helper that always returns an error when reading
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

/*
Integration Tests Needed (require real GitHub API):

1. TestGitHubClient_GetLatestRelease_Success
   - Use real or test GitHub repo
   - Call GetLatestRelease
   - Verify release data is returned
   - Check for rate limiting

2. TestGitHubClient_GetLatestRelease_NoReleases
   - Use repo with no releases
   - Verify appropriate error

3. TestGitHubClient_GetLatestRelease_PrivateRepo
   - Test with private repo (should fail without auth)
   - Test with authenticated client
   - Verify behavior

4. TestGitHubClient_ListReleases_Success
   - Use repo with multiple releases
   - Verify all releases are returned
   - Check ordering

5. TestGitHubClient_ListReleases_Pagination
   - Use repo with >100 releases
   - Verify pagination works correctly
   - Check that all releases are retrieved

6. TestGitHubClient_DownloadAsset_Success
   - Create test release with asset
   - Download the asset
   - Verify file contents
   - Clean up

7. TestGitHubClient_DownloadAsset_RedirectURL
   - Test download when API returns redirect URL
   - Verify redirect is followed correctly
   - Verify file contents

8. TestGitHubClient_DownloadAsset_NonexistentAsset
   - Try to download non-existent asset ID
   - Verify appropriate error

9. TestGitHubClient_DownloadAsset_LargeFile
   - Download large asset (>100MB)
   - Verify download completes
   - Check file integrity

10. TestGitHubClient_Authentication
    - Test with GITHUB_TOKEN environment variable
    - Verify authenticated requests work
    - Check rate limit differences

These integration tests should be in a separate file with build tags like:
  //go:build integration

They would need:
- Real GitHub repository for testing
- GitHub token for authentication (for private repo tests)
- Network connectivity
- Handling of rate limits
- Cleanup of test releases/assets
*/
