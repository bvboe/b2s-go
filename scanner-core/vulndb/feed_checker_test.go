package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test first run behavior: cache created, hasChanged=false
func TestFeedChecker_FirstRun(t *testing.T) {
	// Create mock HTTP server
	listing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"5": {{
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:abc123",
				URL:      "https://example.com/db.tar.gz",
				Version:  5,
			}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(listing); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create feed checker with temp cache directory
	tmpDir := t.TempDir()
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  filepath.Join(tmpDir, "cache.json"),
		httpClient: server.Client(),
	}

	// Test first run
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// First run should NOT trigger rescan
	if hasChanged {
		t.Error("Expected hasChanged=false on first run")
	}

	// Cache should be created
	if _, err := os.Stat(fc.cacheFile); os.IsNotExist(err) {
		t.Error("Cache file was not created")
	}

	// Verify cache content
	cached, err := fc.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if cached.Listing.Available["5"][0].Checksum != "sha256:abc123" {
		t.Errorf("Expected checksum 'sha256:abc123', got '%s'", cached.Listing.Available["5"][0].Checksum)
	}
}

// Test database changed: different checksums, hasChanged=true
func TestFeedChecker_DatabaseChanged(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write initial cache with old checksum
	initialCache := CachedListing{
		LastChecked: time.Now().UTC(),
		Listing: FeedListing{
			Available: map[string][]DatabaseEntry{
				"5": {{
					Built:    "2025-12-26T00:00:00Z",
					Checksum: "sha256:old_checksum",
					URL:      "https://example.com/old.tar.gz",
					Version:  5,
				}},
			},
		},
	}
	data, _ := json.MarshalIndent(initialCache, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write initial cache: %v", err)
	}

	// Create mock server with new checksum
	newListing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"5": {{
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:new_checksum",
				URL:      "https://example.com/new.tar.gz",
				Version:  5,
			}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(newListing); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create feed checker
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  cacheFile,
		httpClient: server.Client(),
	}

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// Should detect change
	if !hasChanged {
		t.Error("Expected hasChanged=true when checksums differ")
	}

	// Cache should be updated
	cached, err := fc.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if cached.Listing.Available["5"][0].Checksum != "sha256:new_checksum" {
		t.Errorf("Expected checksum 'sha256:new_checksum', got '%s'", cached.Listing.Available["5"][0].Checksum)
	}
}

// Test no change: same checksums, hasChanged=false
func TestFeedChecker_NoChange(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write cache with same checksum as server will return
	listing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"5": {{
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:same_checksum",
				URL:      "https://example.com/db.tar.gz",
				Version:  5,
			}},
		},
	}

	cachedListing := CachedListing{
		LastChecked: time.Now().UTC(),
		Listing:     listing,
	}
	data, _ := json.MarshalIndent(cachedListing, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write cache: %v", err)
	}

	// Create mock server returning same listing
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(listing); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create feed checker
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  cacheFile,
		httpClient: server.Client(),
	}

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// Should NOT detect change
	if hasChanged {
		t.Error("Expected hasChanged=false when checksums are the same")
	}
}

// Test network failure: error returned, cache unchanged
func TestFeedChecker_NetworkFailure(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write initial cache
	initialCache := CachedListing{
		LastChecked: time.Now().UTC(),
		Listing: FeedListing{
			Available: map[string][]DatabaseEntry{
				"5": {{
					Built:    "2025-12-26T00:00:00Z",
					Checksum: "sha256:original_checksum",
					URL:      "https://example.com/db.tar.gz",
					Version:  5,
				}},
			},
		},
	}
	data, _ := json.MarshalIndent(initialCache, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write initial cache: %v", err)
	}

	// Create mock server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// Create feed checker
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  cacheFile,
		httpClient: server.Client(),
	}

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err == nil {
		t.Error("Expected error for network failure")
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on error")
	}

	// Cache should remain unchanged
	cached, err := fc.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if cached.Listing.Available["5"][0].Checksum != "sha256:original_checksum" {
		t.Error("Cache should not be modified on error")
	}
}

// Test corrupted cache: recreated as first run
func TestFeedChecker_CorruptedCache(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write corrupted JSON to cache
	if err := os.WriteFile(cacheFile, []byte("not valid json{{{"), 0644); err != nil {
		t.Fatalf("Failed to write corrupted cache: %v", err)
	}

	// Create mock server
	listing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"5": {{
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:new_checksum",
				URL:      "https://example.com/db.tar.gz",
				Version:  5,
			}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(listing); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create feed checker
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  cacheFile,
		httpClient: server.Client(),
	}

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// Should treat as first run (hasChanged=false)
	if hasChanged {
		t.Error("Expected hasChanged=false for corrupted cache (treated as first run)")
	}

	// Cache should be recreated with valid JSON
	cached, err := fc.loadCache()
	if err != nil {
		t.Fatalf("Failed to load recreated cache: %v", err)
	}

	if cached.Listing.Available["5"][0].Checksum != "sha256:new_checksum" {
		t.Error("Cache should be recreated with new data")
	}
}

// Test context cancellation: graceful error
func TestFeedChecker_ContextCancellation(t *testing.T) {
	// Create mock server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay to allow context cancellation
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"available":{}}`)
	}))
	defer server.Close()

	// Create feed checker
	tmpDir := t.TempDir()
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  filepath.Join(tmpDir, "cache.json"),
		httpClient: server.Client(),
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(ctx)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on error")
	}
}

// Test atomic write behavior
func TestFeedChecker_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	fc := &FeedChecker{
		feedURL:   "http://example.com",
		cacheFile: cacheFile,
	}

	listing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"5": {{
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:test",
				URL:      "https://example.com/db.tar.gz",
				Version:  5,
			}},
		},
	}

	// Save cache
	if err := fc.saveCache(listing); err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Verify temp file doesn't exist
	tempFile := cacheFile + ".tmp"
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Error("Temp file should not exist after successful write")
	}

	// Verify cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Error("Cache file should exist after write")
	}

	// Verify content
	cached, err := fc.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if cached.Listing.Available["5"][0].Checksum != "sha256:test" {
		t.Errorf("Expected checksum 'sha256:test', got '%s'", cached.Listing.Available["5"][0].Checksum)
	}
}

// Test missing schema version
func TestFeedChecker_MissingSchemaVersion(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write cache with schema version 5
	initialCache := CachedListing{
		LastChecked: time.Now().UTC(),
		Listing: FeedListing{
			Available: map[string][]DatabaseEntry{
				"5": {{
					Built:    "2025-12-26T00:00:00Z",
					Checksum: "sha256:old",
					URL:      "https://example.com/db.tar.gz",
					Version:  5,
				}},
			},
		},
	}
	data, _ := json.MarshalIndent(initialCache, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write cache: %v", err)
	}

	// Server returns listing without schema version 5
	newListing := FeedListing{
		Available: map[string][]DatabaseEntry{
			"6": {{ // Different schema version
				Built:    "2025-12-27T00:00:00Z",
				Checksum: "sha256:new",
				URL:      "https://example.com/db.tar.gz",
				Version:  6,
			}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(newListing); err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  cacheFile,
		httpClient: server.Client(),
	}

	// Check for updates
	hasChanged, err := fc.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// Should treat as no change (since we can't compare)
	if hasChanged {
		t.Error("Expected hasChanged=false when schema version is missing")
	}
}

// Test NewFeedChecker creates cache directory
func TestNewFeedChecker_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "nonexistent", "cache")

	fc, err := NewFeedChecker(cacheDir)
	if err != nil {
		t.Fatalf("NewFeedChecker failed: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		t.Error("Cache directory should be created")
	}

	// Verify cache file path
	expectedCacheFile := filepath.Join(cacheDir, CacheFilename)
	if fc.cacheFile != expectedCacheFile {
		t.Errorf("Expected cache file '%s', got '%s'", expectedCacheFile, fc.cacheFile)
	}
}

// Test NewFeedChecker with empty cache dir
func TestNewFeedChecker_EmptyCacheDir(t *testing.T) {
	_, err := NewFeedChecker("")
	if err == nil {
		t.Error("Expected error for empty cacheDir")
	}
}
