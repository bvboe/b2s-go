package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

func TestNewDatabaseUpdater(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Verify grype directory was created
	grypeDir := filepath.Join(tmpDir, "grype")
	if _, err := os.Stat(grypeDir); os.IsNotExist(err) {
		t.Error("grype directory should be created")
	}

	// Verify cache file path
	expectedCacheFile := filepath.Join(tmpDir, DatabaseCacheFilename)
	if du.cacheFile != expectedCacheFile {
		t.Errorf("Expected cache file '%s', got '%s'", expectedCacheFile, du.cacheFile)
	}
}

func TestNewDatabaseUpdater_EmptyDir(t *testing.T) {
	_, err := NewDatabaseUpdater("")
	if err == nil {
		t.Error("Expected error for empty dbRootDir")
	}
}

func TestDatabaseUpdater_CacheOperations(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Test saving cache
	state := DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC),
		SchemaVersion: "v6.1.3",
		Path:          "/test/path",
	}

	if err := du.saveCache(state); err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	// Verify cache file exists
	if _, err := os.Stat(du.cacheFile); os.IsNotExist(err) {
		t.Error("Cache file should exist after save")
	}

	// Test loading cache
	loaded, err := du.loadCache()
	if err != nil {
		t.Fatalf("loadCache failed: %v", err)
	}

	if loaded.SchemaVersion != state.SchemaVersion {
		t.Errorf("Expected schema version '%s', got '%s'", state.SchemaVersion, loaded.SchemaVersion)
	}

	if !loaded.Built.Equal(state.Built) {
		t.Errorf("Expected built time '%v', got '%v'", state.Built, loaded.Built)
	}
}

func TestDatabaseUpdater_CorruptedCache(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Write corrupted JSON to cache
	if err := os.WriteFile(du.cacheFile, []byte("not valid json{{{"), 0644); err != nil {
		t.Fatalf("Failed to write corrupted cache: %v", err)
	}

	// loadCache should return error and delete corrupted file
	_, err = du.loadCache()
	if !os.IsNotExist(err) {
		t.Errorf("Expected os.ErrNotExist for corrupted cache, got: %v", err)
	}

	// Corrupted cache file should be deleted
	if _, err := os.Stat(du.cacheFile); !os.IsNotExist(err) {
		t.Error("Corrupted cache file should be deleted")
	}
}

func TestDatabaseUpdater_NoCacheFirstRun(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// loadCache should return error for missing cache
	_, err = du.loadCache()
	if !os.IsNotExist(err) {
		t.Errorf("Expected os.ErrNotExist for missing cache, got: %v", err)
	}
}

func TestDatabaseUpdater_AtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	state := DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC),
		SchemaVersion: "v6.1.3",
		Path:          "/test/path",
	}

	// Save cache
	if err := du.saveCache(state); err != nil {
		t.Fatalf("saveCache failed: %v", err)
	}

	// Verify temp file doesn't exist (was renamed)
	tempFile := du.cacheFile + ".tmp"
	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Error("Temp file should not exist after successful write")
	}

	// Verify cache file is valid JSON
	data, err := os.ReadFile(du.cacheFile)
	if err != nil {
		t.Fatalf("Failed to read cache file: %v", err)
	}

	var loaded DatabaseState
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Errorf("Cache file should contain valid JSON: %v", err)
	}
}

// Tests for CheckForUpdates using mock loader

func TestDatabaseUpdater_CheckForUpdates_FirstRun(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Mock loader returns a database status
	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// First run should return false (no change detected on first run)
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on first run")
	}

	// Cache should be created
	cached, err := du.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if !cached.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, cached.Built)
	}
}

func TestDatabaseUpdater_CheckForUpdates_DatabaseChanged(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Pre-populate cache with old timestamp
	oldBuilt := time.Date(2025, 12, 26, 0, 0, 0, 0, time.UTC)
	if err := du.saveCache(DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         oldBuilt,
		SchemaVersion: "v6.1.2",
		Path:          "/old/path",
	}); err != nil {
		t.Fatalf("Failed to save initial cache: %v", err)
	}

	// Mock loader returns NEW database status
	newBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         newBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/new/path",
		}, nil
	})

	// Should detect change
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if !hasChanged {
		t.Error("Expected hasChanged=true when Built timestamp differs")
	}

	// Cache should be updated
	cached, err := du.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if !cached.Built.Equal(newBuilt) {
		t.Errorf("Expected built time %v, got %v", newBuilt, cached.Built)
	}
}

func TestDatabaseUpdater_CheckForUpdates_NoChange(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Same timestamp for both cache and mock
	sameBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)

	// Pre-populate cache
	if err := du.saveCache(DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         sameBuilt,
		SchemaVersion: "v6.1.3",
		Path:          "/test/path",
	}); err != nil {
		t.Fatalf("Failed to save initial cache: %v", err)
	}

	// Mock loader returns same timestamp
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         sameBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Should NOT detect change
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if hasChanged {
		t.Error("Expected hasChanged=false when Built timestamps are equal")
	}
}

func TestDatabaseUpdater_CheckForUpdates_LoaderError(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Mock loader returns error
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return nil, fmt.Errorf("network error")
	})

	hasChanged, err := du.CheckForUpdates(context.Background())
	if err == nil {
		t.Error("Expected error when loader fails")
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on error")
	}
}

func TestDatabaseUpdater_CheckForUpdates_ZeroTimestamps(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Pre-populate cache with valid timestamp
	oldBuilt := time.Date(2025, 12, 26, 0, 0, 0, 0, time.UTC)
	if err := du.saveCache(DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         oldBuilt,
		SchemaVersion: "v6.1.2",
		Path:          "/old/path",
	}); err != nil {
		t.Fatalf("Failed to save initial cache: %v", err)
	}

	// Mock loader returns zero timestamp (edge case)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         time.Time{}, // Zero time
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Should NOT detect change when one timestamp is zero
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if hasChanged {
		t.Error("Expected hasChanged=false when new Built timestamp is zero")
	}
}

func TestDatabaseUpdater_GetCurrentStatus(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		// Verify update=false is passed
		if update {
			t.Error("GetCurrentStatus should call loader with update=false")
		}
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	status, err := du.GetCurrentStatus(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentStatus failed: %v", err)
	}

	if !status.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, status.Built)
	}
}
