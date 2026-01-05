package vulndb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test first run behavior: cache created, hasChanged=false
func TestFeedChecker_FirstRun(t *testing.T) {
	// Create mock HTTP server returning v6 format
	dbInfo := DatabaseInfo{
		Status:        "active",
		SchemaVersion: "v6.1.3",
		Built:         "2025-12-27T00:00:00Z",
		Path:          "vulnerability-db_v6.1.3_2025-12-27T00:00:00Z.tar.zst",
		Checksum:      "sha256:abc123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(dbInfo); err != nil {
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

	if cached.DatabaseInfo.Checksum != "sha256:abc123" {
		t.Errorf("Expected checksum 'sha256:abc123', got '%s'", cached.DatabaseInfo.Checksum)
	}
}

// Test database changed: different checksums, hasChanged=true
func TestFeedChecker_DatabaseChanged(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Write initial cache with old checksum
	initialCache := CachedDatabaseInfo{
		LastChecked: time.Now().UTC(),
		DatabaseInfo: DatabaseInfo{
			Status:        "active",
			SchemaVersion: "v6.1.2",
			Built:         "2025-12-26T00:00:00Z",
			Path:          "vulnerability-db_v6.1.2_2025-12-26T00:00:00Z.tar.zst",
			Checksum:      "sha256:old_checksum",
		},
	}
	data, _ := json.MarshalIndent(initialCache, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write initial cache: %v", err)
	}

	// Create mock server with new checksum
	newDbInfo := DatabaseInfo{
		Status:        "active",
		SchemaVersion: "v6.1.3",
		Built:         "2025-12-27T00:00:00Z",
		Path:          "vulnerability-db_v6.1.3_2025-12-27T00:00:00Z.tar.zst",
		Checksum:      "sha256:new_checksum",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(newDbInfo); err != nil {
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

	if cached.DatabaseInfo.Checksum != "sha256:new_checksum" {
		t.Errorf("Expected checksum 'sha256:new_checksum', got '%s'", cached.DatabaseInfo.Checksum)
	}
}

// Test no change: same checksums, hasChanged=false
func TestFeedChecker_NoChange(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "cache.json")

	// Database info that will be used for both cache and server
	dbInfo := DatabaseInfo{
		Status:        "active",
		SchemaVersion: "v6.1.3",
		Built:         "2025-12-27T00:00:00Z",
		Path:          "vulnerability-db_v6.1.3_2025-12-27T00:00:00Z.tar.zst",
		Checksum:      "sha256:same_checksum",
	}

	// Write cache with same checksum as server will return
	cachedInfo := CachedDatabaseInfo{
		LastChecked:  time.Now().UTC(),
		DatabaseInfo: dbInfo,
	}
	data, _ := json.MarshalIndent(cachedInfo, "", "  ")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		t.Fatalf("Failed to write cache: %v", err)
	}

	// Create mock server returning same info
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(dbInfo); err != nil {
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
	initialCache := CachedDatabaseInfo{
		LastChecked: time.Now().UTC(),
		DatabaseInfo: DatabaseInfo{
			Status:        "active",
			SchemaVersion: "v6.1.3",
			Built:         "2025-12-26T00:00:00Z",
			Path:          "vulnerability-db_v6.1.3_2025-12-26T00:00:00Z.tar.zst",
			Checksum:      "sha256:original_checksum",
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

	if cached.DatabaseInfo.Checksum != "sha256:original_checksum" {
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
	dbInfo := DatabaseInfo{
		Status:        "active",
		SchemaVersion: "v6.1.3",
		Built:         "2025-12-27T00:00:00Z",
		Path:          "vulnerability-db_v6.1.3_2025-12-27T00:00:00Z.tar.zst",
		Checksum:      "sha256:new_checksum",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(dbInfo); err != nil {
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

	if cached.DatabaseInfo.Checksum != "sha256:new_checksum" {
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
		_, _ = w.Write([]byte(`{"status":"active","schemaVersion":"v6.1.3","built":"2025-12-27T00:00:00Z","path":"db.tar.zst","checksum":"sha256:abc"}`))
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

	dbInfo := DatabaseInfo{
		Status:        "active",
		SchemaVersion: "v6.1.3",
		Built:         "2025-12-27T00:00:00Z",
		Path:          "vulnerability-db_v6.1.3_2025-12-27T00:00:00Z.tar.zst",
		Checksum:      "sha256:test",
	}

	// Save cache
	if err := fc.saveCache(dbInfo); err != nil {
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

	if cached.DatabaseInfo.Checksum != "sha256:test" {
		t.Errorf("Expected checksum 'sha256:test', got '%s'", cached.DatabaseInfo.Checksum)
	}
}

// Test missing checksum in response
func TestFeedChecker_MissingChecksum(t *testing.T) {
	// Create mock server returning invalid response (no checksum)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"active","schemaVersion":"v6.1.3","built":"2025-12-27T00:00:00Z","path":"db.tar.zst"}`))
	}))
	defer server.Close()

	// Create feed checker
	tmpDir := t.TempDir()
	fc := &FeedChecker{
		feedURL:    server.URL,
		cacheFile:  filepath.Join(tmpDir, "cache.json"),
		httpClient: server.Client(),
	}

	// Check for updates - should fail because checksum is missing
	_, err := fc.CheckForUpdates(context.Background())
	if err == nil {
		t.Error("Expected error for missing checksum")
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

// Test truncateChecksum helper function
func TestTruncateChecksum(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sha256:abc123def456", "sha256:abc123def456"},                         // Short - no truncation (14 chars)
		{"sha256:abcdefghijklmnopqrstuvwxyz", "sha256:abcdefghijklm..."},       // Long - truncated at 20 chars
		{"sha256:d46d2d9b09d90042801d80f4fdee067c79046d64b12d6fcf650a1955cd6b7a43", "sha256:d46d2d9b09d90..."},
		{"", ""},                                                                // Empty
		{"short", "short"},                                                      // Very short
	}

	for _, test := range tests {
		result := truncateChecksum(test.input)
		if result != test.expected {
			t.Errorf("truncateChecksum(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}
