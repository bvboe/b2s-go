package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

const (
	// DatabaseCacheFilename stores the last known database state
	DatabaseCacheFilename = "grype_db_state.json"
)

// DatabaseState represents the cached state of the vulnerability database
type DatabaseState struct {
	LastChecked   time.Time `json:"last_checked"`
	Built         time.Time `json:"built"`
	SchemaVersion string    `json:"schema_version"`
	Path          string    `json:"path"`
}

// DatabaseLoader is the function signature for loading the vulnerability database
// This allows mocking in tests
type DatabaseLoader func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error)

// DatabaseStatus mirrors the relevant fields from grype's ProviderStatus
type DatabaseStatus struct {
	Built         time.Time
	SchemaVersion string
	Path          string
}

// defaultDatabaseLoader wraps grype.LoadVulnerabilityDB
func defaultDatabaseLoader(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
	_, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, update)
	if err != nil {
		return nil, err
	}
	return &DatabaseStatus{
		Built:         dbStatus.Built,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}, nil
}

// DatabaseUpdater uses grype's native update mechanism to check for database updates
type DatabaseUpdater struct {
	dbRootDir  string
	cacheFile  string
	distCfg    distribution.Config
	installCfg installation.Config
	loader     DatabaseLoader // injectable for testing
	mu         sync.Mutex
}

// NewDatabaseUpdater creates a new database updater
// dbRootDir is the root directory where grype stores its database (e.g., /var/lib/bjorn2scan)
func NewDatabaseUpdater(dbRootDir string) (*DatabaseUpdater, error) {
	if dbRootDir == "" {
		return nil, fmt.Errorf("dbRootDir cannot be empty")
	}

	// Ensure directory exists
	grypeDir := filepath.Join(dbRootDir, "grype")
	if err := os.MkdirAll(grypeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create grype directory: %w", err)
	}

	cacheFile := filepath.Join(dbRootDir, DatabaseCacheFilename)

	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}

	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification

	installCfg := installation.DefaultConfig(identification)
	installCfg.DBRootDir = grypeDir

	return &DatabaseUpdater{
		dbRootDir:  dbRootDir,
		cacheFile:  cacheFile,
		distCfg:    distCfg,
		installCfg: installCfg,
		loader:     defaultDatabaseLoader,
	}, nil
}

// SetLoader sets a custom database loader (for testing)
func (du *DatabaseUpdater) SetLoader(loader DatabaseLoader) {
	du.loader = loader
}

// CheckForUpdates checks if the vulnerability database has been updated
// It uses grype's native update mechanism and compares the Built timestamp
// Returns: (hasChanged bool, error)
// On first run (no cache), it returns (false, nil) after caching the current state
func (du *DatabaseUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	// 1. Load cached state (if exists)
	cachedState, err := du.loadCache()
	isFirstRun := err != nil

	if isFirstRun {
		if !os.IsNotExist(err) {
			log.Printf("[db-updater] Warning: failed to load cache: %v", err)
		}
	} else {
		log.Printf("[db-updater] Cached database state: built=%v, schema=%s",
			cachedState.Built.Format(time.RFC3339), cachedState.SchemaVersion)
	}

	// 2. Run grype database update (this checks feed and downloads if needed)
	log.Printf("[db-updater] Checking for vulnerability database updates...")
	startTime := time.Now()

	// Progress indicator for long updates
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				log.Printf("[db-updater] Still updating database... (%v elapsed)", elapsed)
			}
		}
	}()

	// Load with update=true to trigger the update check
	dbStatus, err := du.loader(du.distCfg, du.installCfg, true)
	close(done)

	updateDuration := time.Since(startTime).Round(time.Millisecond)

	if err != nil {
		log.Printf("[db-updater] Failed to update database after %v: %v", updateDuration, err)
		return false, fmt.Errorf("failed to update vulnerability database: %w", err)
	}

	log.Printf("[db-updater] Database check completed in %v", updateDuration)
	log.Printf("[db-updater] Current database: built=%v, schema=%s, path=%s",
		dbStatus.Built.Format(time.RFC3339), dbStatus.SchemaVersion, dbStatus.Path)

	// 3. Compare with cached state
	hasChanged := false
	if !isFirstRun && !dbStatus.Built.IsZero() && !cachedState.Built.IsZero() {
		hasChanged = !dbStatus.Built.Equal(cachedState.Built)
		if hasChanged {
			log.Printf("[db-updater] Database update detected: %v -> %v",
				cachedState.Built.Format(time.RFC3339), dbStatus.Built.Format(time.RFC3339))
		} else {
			log.Printf("[db-updater] No database changes detected")
		}
	} else if isFirstRun {
		log.Printf("[db-updater] First run detected, caching database state without triggering rescan")
	}

	// 4. Save current state to cache
	newState := DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         dbStatus.Built,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}
	if err := du.saveCache(newState); err != nil {
		log.Printf("[db-updater] Warning: failed to save cache: %v", err)
		// Don't fail the whole operation for cache save failure
	}

	return hasChanged, nil
}

// GetCurrentStatus returns the current database status without triggering an update
func (du *DatabaseUpdater) GetCurrentStatus(ctx context.Context) (*DatabaseState, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	// Load database without update to get current status
	dbStatus, err := du.loader(du.distCfg, du.installCfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load database status: %w", err)
	}

	return &DatabaseState{
		LastChecked:   time.Now().UTC(),
		Built:         dbStatus.Built,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}, nil
}

// loadCache reads the cached database state from disk
func (du *DatabaseUpdater) loadCache() (*DatabaseState, error) {
	data, err := os.ReadFile(du.cacheFile)
	if err != nil {
		return nil, err
	}

	var state DatabaseState
	if err := json.Unmarshal(data, &state); err != nil {
		// Treat corrupted cache as first run
		log.Printf("[db-updater] Warning: corrupted cache, recreating: %v", err)
		if removeErr := os.Remove(du.cacheFile); removeErr != nil {
			log.Printf("[db-updater] Warning: failed to remove corrupted cache: %v", removeErr)
		}
		return nil, os.ErrNotExist
	}

	return &state, nil
}

// saveCache writes the database state to disk atomically
func (du *DatabaseUpdater) saveCache(state DatabaseState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := du.cacheFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, du.cacheFile); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}
