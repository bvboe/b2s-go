package vulndb

import (
	"context"
	"database/sql"
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
	// Note: sqlite driver is registered by grype's dependencies (modernc.org/sqlite)
)

// DatabaseLoader is the function signature for loading the vulnerability database
// This allows mocking in tests
type DatabaseLoader func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error)

// DescriptionReader is the function signature for reading the database description
// This allows mocking in tests to simulate reading the actual db file timestamp
type DescriptionReader func(dbPath string) (time.Time, error)

// TimestampStore is the interface for persisting the last known grype DB timestamp
// This is used to track database changes across process restarts
type TimestampStore interface {
	LoadGrypeDBTimestamp() (time.Time, error)
	SaveGrypeDBTimestamp(t time.Time) error
}

// DatabaseStatus mirrors the relevant fields from grype's ProviderStatus
type DatabaseStatus struct {
	Built         time.Time
	SchemaVersion string
	Path          string
}

// readGrypeDBTimestampFromSQLite reads the database build timestamp directly from
// the grype SQLite database file, bypassing grype's library which may cache stale values.
// This is the authoritative source for the database timestamp.
// Uses the pure Go SQLite driver (modernc.org/sqlite) which doesn't require CGO.
func readGrypeDBTimestampFromSQLite(dbPath string) (time.Time, error) {
	// Use the pure Go SQLite driver (registered as "sqlite" by modernc.org/sqlite)
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open grype database: %w", err)
	}
	defer func() { _ = db.Close() }()

	var builtStr string
	err = db.QueryRow("SELECT build_timestamp FROM db_metadata LIMIT 1").Scan(&builtStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read db_metadata: %w", err)
	}

	// Parse the timestamp - grype v6 uses RFC3339 format like "2026-01-16T06:16:58Z"
	// but older versions used "2026-01-13 08:06:41+00:00"
	t, err := time.Parse(time.RFC3339, builtStr)
	if err != nil {
		// Try legacy format with space separator
		t, err = time.Parse("2006-01-02 15:04:05-07:00", builtStr)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05+00:00", builtStr)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse timestamp %q: %w", builtStr, err)
			}
		}
	}

	return t.UTC(), nil
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
	dbRootDir         string
	distCfg           distribution.Config
	installCfg        installation.Config
	loader            DatabaseLoader    // injectable for testing
	descriptionReader DescriptionReader // injectable for testing (reads actual db timestamp)
	timestampStore    TimestampStore    // persistent storage for tracking DB changes
	mu                sync.RWMutex
	currentVersion    *DatabaseStatus // in-memory current version for metrics
}

// DatabaseUpdaterConfig holds optional configuration for DatabaseUpdater
type DatabaseUpdaterConfig struct {
	// LatestURL overrides the default grype database feed URL
	// If empty, uses the official Anchore feed
	LatestURL string
	// TimestampStore is used to persist the last known grype DB timestamp
	// This enables reliable change detection across process restarts
	TimestampStore TimestampStore
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
		dbRootDir:      dbRootDir,
		distCfg:        distCfg,
		installCfg:     installCfg,
		loader:         defaultDatabaseLoader,
		timestampStore: cfg.TimestampStore,
	}, nil
}

// SetTimestampStore sets the timestamp store for persistent tracking
func (du *DatabaseUpdater) SetTimestampStore(store TimestampStore) {
	du.timestampStore = store
}

// SetLoader sets a custom database loader (for testing)
func (du *DatabaseUpdater) SetLoader(loader DatabaseLoader) {
	du.loader = loader
}

// SetDescriptionReader sets a custom description reader (for testing)
// This allows tests to mock the actual database file timestamp
func (du *DatabaseUpdater) SetDescriptionReader(reader DescriptionReader) {
	du.descriptionReader = reader
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

	// 1. Get the last known timestamp from persistent storage
	// This is more reliable than reading from the grype library which may cache stale values
	var lastKnownTimestamp time.Time
	if du.timestampStore != nil {
		if t, err := du.timestampStore.LoadGrypeDBTimestamp(); err == nil && !t.IsZero() {
			lastKnownTimestamp = t
			log.Printf("[db-updater] Last known DB timestamp (from persistent store): %s",
				lastKnownTimestamp.Format(time.RFC3339))
		} else if err != nil {
			log.Printf("[db-updater] Warning: failed to load last known timestamp: %v", err)
		}
	}

	// 2. Check if database file exists and if update is available
	dbExisted := false
	if _, err := os.Stat(dbPath); err == nil {
		dbExisted = true
		desc, err := v6.ReadDescription(dbPath)
		if err != nil {
			log.Printf("[db-updater] Warning: failed to read database description: %v", err)
		} else {
			log.Printf("[db-updater] Current database file: built=%s, schema=%s",
				desc.Built.Format(time.RFC3339), desc.SchemaVersion.String())

			// Check if a newer archive is available
			client, err := distribution.NewClient(du.distCfg)
			if err != nil {
				log.Printf("[db-updater] Warning: failed to create distribution client: %v", err)
			} else {
				archive, err := client.IsUpdateAvailable(desc)
				if err != nil {
					log.Printf("[db-updater] Warning: failed to check for updates: %v", err)
				} else if archive != nil {
					// Use persistent timestamp for comparison if available, as v6.ReadDescription
					// may return stale cached values that don't match the actual database
					compareTimestamp := desc.Built.Time
					if !lastKnownTimestamp.IsZero() {
						compareTimestamp = lastKnownTimestamp
						log.Printf("[db-updater] Using persistent timestamp for comparison: %s",
							compareTimestamp.Format(time.RFC3339))
					}

					if archive.Built.After(compareTimestamp) {
						// Newer database available - delete existing to force re-download
						log.Printf("[db-updater] Update available: archive built=%s (current=%s)",
							archive.Built.Format(time.RFC3339), compareTimestamp.Format(time.RFC3339))
						log.Printf("[db-updater] Removing existing database to force update...")
						schemaDir := filepath.Join(grypeDir, "6")
						if err := os.RemoveAll(schemaDir); err != nil {
							log.Printf("[db-updater] Warning: failed to remove schema dir: %v", err)
						}
					} else {
						log.Printf("[db-updater] Archive available but not newer: archive=%s, current=%s",
							archive.Built.Format(time.RFC3339), compareTimestamp.Format(time.RFC3339))
					}
				} else {
					log.Printf("[db-updater] No update available")
				}
			}
		}
	} else {
		log.Printf("[db-updater] No existing database found, will download")
	}

	// 3. Load/download the database
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

	log.Printf("[db-updater] Loader returned: built=%s, schema=%s (took %v)",
		dbStatus.Built.Format(time.RFC3339), dbStatus.SchemaVersion,
		time.Since(startTime).Round(time.Millisecond))

	// 4. Read the actual database timestamp directly from SQLite
	// This bypasses grype's library which may cache stale values
	var actualBuilt time.Time
	if du.descriptionReader != nil {
		// Use injected reader (for testing)
		if t, err := du.descriptionReader(dbPath); err == nil {
			actualBuilt = t
		} else {
			log.Printf("[db-updater] Warning: descriptionReader failed: %v", err)
			actualBuilt = dbStatus.Built
		}
	} else {
		// Read directly from SQLite - this is the authoritative source
		if t, err := readGrypeDBTimestampFromSQLite(dbPath); err == nil {
			actualBuilt = t
			if !actualBuilt.Equal(dbStatus.Built) {
				log.Printf("[db-updater] Corrected timestamp: loader=%s, actual=%s",
					dbStatus.Built.Format(time.RFC3339), actualBuilt.Format(time.RFC3339))
			}
		} else {
			log.Printf("[db-updater] Warning: failed to read timestamp from SQLite: %v", err)
			// Fall back to v6.ReadDescription
			if desc, err := v6.ReadDescription(dbPath); err == nil {
				actualBuilt = desc.Built.Time
			} else {
				log.Printf("[db-updater] Warning: failed to re-read database description: %v", err)
				actualBuilt = dbStatus.Built
			}
		}
	}

	// Store current version in memory for metrics (using actual timestamp)
	du.currentVersion = &DatabaseStatus{
		Built:         actualBuilt,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}

	log.Printf("[db-updater] Database ready: built=%s, schema=%s",
		actualBuilt.Format(time.RFC3339), dbStatus.SchemaVersion)

	// 5. Determine if database changed by comparing against persistent timestamp
	// This is more reliable than comparing against in-memory values which may be stale
	var hasChanged bool
	if !dbExisted && lastKnownTimestamp.IsZero() {
		// First run - database was just downloaded, nothing to rescan yet
		log.Printf("[db-updater] Initial database download complete, no rescan needed")
		hasChanged = false
	} else if lastKnownTimestamp.IsZero() {
		// Database existed but we have no persistent record - this is a migration scenario
		// Don't trigger rescan, just record the current timestamp
		log.Printf("[db-updater] No persistent timestamp record, initializing tracking")
		hasChanged = false
	} else {
		// Compare actual timestamp against persisted last known timestamp
		hasChanged = !actualBuilt.Equal(lastKnownTimestamp)
		if hasChanged {
			log.Printf("[db-updater] Database updated: %s -> %s",
				lastKnownTimestamp.Format(time.RFC3339), actualBuilt.Format(time.RFC3339))
		} else {
			log.Printf("[db-updater] No database changes (persistent comparison)")
		}
	}

	// 6. Save the current timestamp to persistent storage
	if du.timestampStore != nil {
		if err := du.timestampStore.SaveGrypeDBTimestamp(actualBuilt); err != nil {
			log.Printf("[db-updater] Warning: failed to save timestamp to persistent store: %v", err)
		} else {
			log.Printf("[db-updater] Saved DB timestamp to persistent store: %s",
				actualBuilt.Format(time.RFC3339))
		}
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
