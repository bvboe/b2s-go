package vulndb

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

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
	dbRootDir      string
	distCfg        distribution.Config
	installCfg     installation.Config
	loader         DatabaseLoader  // injectable for testing
	mu             sync.RWMutex
	currentVersion *DatabaseStatus // in-memory current version for metrics
}

// DatabaseUpdaterConfig holds optional configuration for DatabaseUpdater
type DatabaseUpdaterConfig struct {
	// LatestURL overrides the default grype database feed URL
	// If empty, uses the official Anchore feed
	LatestURL string
}

// NewDatabaseUpdater creates a new database updater
// dbRootDir is the root directory where grype stores its database (e.g., /var/lib/bjorn2scan)
func NewDatabaseUpdater(dbRootDir string) (*DatabaseUpdater, error) {
	return NewDatabaseUpdaterWithConfig(dbRootDir, DatabaseUpdaterConfig{})
}

// NewDatabaseUpdaterWithConfig creates a new database updater with custom configuration
func NewDatabaseUpdaterWithConfig(dbRootDir string, cfg DatabaseUpdaterConfig) (*DatabaseUpdater, error) {
	if dbRootDir == "" {
		return nil, fmt.Errorf("dbRootDir cannot be empty")
	}

	// Ensure directory exists
	grypeDir := filepath.Join(dbRootDir, "grype")
	if err := os.MkdirAll(grypeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create grype directory: %w", err)
	}

	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}

	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification
	if cfg.LatestURL != "" {
		distCfg.LatestURL = cfg.LatestURL
	}

	installCfg := installation.DefaultConfig(identification)
	installCfg.DBRootDir = grypeDir

	return &DatabaseUpdater{
		dbRootDir:  dbRootDir,
		distCfg:    distCfg,
		installCfg: installCfg,
		loader:     defaultDatabaseLoader,
	}, nil
}

// SetLoader sets a custom database loader (for testing)
func (du *DatabaseUpdater) SetLoader(loader DatabaseLoader) {
	du.loader = loader
}

// GetCurrentVersion returns the current database version from memory (thread-safe)
// Returns nil if no database has been loaded yet
func (du *DatabaseUpdater) GetCurrentVersion() *DatabaseStatus {
	du.mu.RLock()
	defer du.mu.RUnlock()
	if du.currentVersion == nil {
		return nil
	}
	// Return a copy to avoid race conditions
	return &DatabaseStatus{
		Built:         du.currentVersion.Built,
		SchemaVersion: du.currentVersion.SchemaVersion,
		Path:          du.currentVersion.Path,
	}
}

// CheckForUpdates checks if the vulnerability database has been updated
// Returns: (hasChanged bool, error)
// - If no database exists, downloads one and returns (false, nil) - nothing to rescan yet
// - If database exists and gets updated, returns (true, nil)
// - If database exists and no update available, returns (false, nil)
func (du *DatabaseUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	log.Printf("[db-updater] Checking for vulnerability database updates...")

	grypeDir := filepath.Join(du.dbRootDir, "grype")
	dbPath := filepath.Join(grypeDir, "6", "vulnerability.db")

	// 1. Read current Built timestamp (if database exists)
	var builtBefore time.Time
	dbExisted := false

	if _, err := os.Stat(dbPath); err == nil {
		dbExisted = true
		desc, err := v6.ReadDescription(dbPath)
		if err != nil {
			log.Printf("[db-updater] Warning: failed to read database description: %v", err)
		} else {
			builtBefore = desc.Built.Time
			log.Printf("[db-updater] Current database: built=%s, schema=%s",
				desc.Built.Format(time.RFC3339), desc.SchemaVersion.String())

			// Check if a newer archive is available
			client, err := distribution.NewClient(du.distCfg)
			if err != nil {
				log.Printf("[db-updater] Warning: failed to create distribution client: %v", err)
			} else {
				archive, err := client.IsUpdateAvailable(desc)
				if err != nil {
					log.Printf("[db-updater] Warning: failed to check for updates: %v", err)
				} else if archive != nil && archive.Built.After(desc.Built.Time) {
					// Newer database available - delete existing to force re-download
					log.Printf("[db-updater] Update available: archive built=%s (current=%s)",
						archive.Built.Format(time.RFC3339), desc.Built.Format(time.RFC3339))
					log.Printf("[db-updater] Removing existing database to force update...")
					schemaDir := filepath.Join(grypeDir, "6")
					if err := os.RemoveAll(schemaDir); err != nil {
						log.Printf("[db-updater] Warning: failed to remove schema dir: %v", err)
					}
				} else if archive != nil {
					log.Printf("[db-updater] Archive available but not newer: archive=%s, current=%s",
						archive.Built.Format(time.RFC3339), desc.Built.Format(time.RFC3339))
				} else {
					log.Printf("[db-updater] No update available")
				}
			}
		}
	} else {
		log.Printf("[db-updater] No existing database found, will download")
	}

	// 2. Load/download the database
	startTime := time.Now()

	// Progress indicator for long downloads
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

	dbStatus, err := du.loader(du.distCfg, du.installCfg, true)
	close(done)

	if err != nil {
		return false, fmt.Errorf("failed to update vulnerability database: %w", err)
	}

	log.Printf("[db-updater] Database ready: built=%s, schema=%s (took %v)",
		dbStatus.Built.Format(time.RFC3339), dbStatus.SchemaVersion,
		time.Since(startTime).Round(time.Millisecond))

	// Store current version in memory for metrics
	du.currentVersion = dbStatus

	// 3. Determine if database changed
	if !dbExisted {
		// First run - database was just downloaded, nothing to rescan yet
		log.Printf("[db-updater] Initial database download complete, no rescan needed")
		return false, nil
	}

	hasChanged := !dbStatus.Built.Equal(builtBefore)
	if hasChanged {
		log.Printf("[db-updater] Database updated: %s -> %s",
			builtBefore.Format(time.RFC3339), dbStatus.Built.Format(time.RFC3339))
	} else {
		log.Printf("[db-updater] No database changes")
	}

	return hasChanged, nil
}

// GetCurrentStatus returns the current database status without triggering an update
// Note: Prefer GetCurrentVersion() for quick in-memory access
func (du *DatabaseUpdater) GetCurrentStatus(ctx context.Context) (*DatabaseStatus, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	dbStatus, err := du.loader(du.distCfg, du.installCfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load database status: %w", err)
	}

	// Also update in-memory version
	du.currentVersion = dbStatus

	return dbStatus, nil
}
