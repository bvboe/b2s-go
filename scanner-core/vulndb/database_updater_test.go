package vulndb

import (
	"context"
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

	// Verify currentVersion is nil initially
	if du.GetCurrentVersion() != nil {
		t.Error("currentVersion should be nil initially")
	}
}

func TestNewDatabaseUpdater_EmptyDir(t *testing.T) {
	_, err := NewDatabaseUpdater("")
	if err == nil {
		t.Error("Expected error for empty dbRootDir")
	}
}

func TestDatabaseUpdater_GetCurrentVersion(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Initially nil
	if du.GetCurrentVersion() != nil {
		t.Error("GetCurrentVersion should return nil before any database load")
	}

	// Mock loader sets the version
	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Call CheckForUpdates to populate the version
	_, _ = du.CheckForUpdates(context.Background())

	// Now it should return the version
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("GetCurrentVersion should return non-nil after CheckForUpdates")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, version.Built)
	}

	if version.SchemaVersion != "v6.1.3" {
		t.Errorf("Expected schema version v6.1.3, got %s", version.SchemaVersion)
	}
}

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

	// First run should return false (no database existed, so no change to detect)
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on first run (no previous database)")
	}

	// Version should be stored in memory
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("Version should be stored after CheckForUpdates")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, version.Built)
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

	// Version should remain nil on error
	if du.GetCurrentVersion() != nil {
		t.Error("Version should be nil after loader error")
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

	// GetCurrentStatus should also update in-memory version
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("GetCurrentVersion should return non-nil after GetCurrentStatus")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected in-memory built time %v, got %v", mockBuilt, version.Built)
	}
}

func TestDatabaseUpdater_GetCurrentVersion_ReturnsCopy(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Populate version
	_, _ = du.CheckForUpdates(context.Background())

	// Get two copies
	v1 := du.GetCurrentVersion()
	v2 := du.GetCurrentVersion()

	// Modify v1
	v1.SchemaVersion = "modified"

	// v2 should not be affected (they should be independent copies)
	if v2.SchemaVersion == "modified" {
		t.Error("GetCurrentVersion should return a copy, not the same pointer")
	}
}

func TestNewDatabaseUpdaterWithConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DatabaseUpdaterConfig{
		LatestURL: "https://custom.example.com/grype/db",
	}

	du, err := NewDatabaseUpdaterWithConfig(tmpDir, cfg)
	if err != nil {
		t.Fatalf("NewDatabaseUpdaterWithConfig failed: %v", err)
	}

	// Verify grype directory was created
	grypeDir := filepath.Join(tmpDir, "grype")
	if _, err := os.Stat(grypeDir); os.IsNotExist(err) {
		t.Error("grype directory should be created")
	}

	// Verify the custom URL was set (we can check via the distCfg)
	if du.distCfg.LatestURL != cfg.LatestURL {
		t.Errorf("Expected LatestURL '%s', got '%s'", cfg.LatestURL, du.distCfg.LatestURL)
	}
}
