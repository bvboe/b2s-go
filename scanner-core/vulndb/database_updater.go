package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
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

	// Log diagnostics BEFORE update
	diagBefore := du.logDatabaseDiagnostics("BEFORE")

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

	// Log diagnostics AFTER update
	diagAfter := du.logDatabaseDiagnostics("AFTER")

	// Compare before/after to see if file actually changed
	if diagBefore.DBChecksum != "" && diagAfter.DBChecksum != "" {
		if diagBefore.DBChecksum != diagAfter.DBChecksum {
			log.Printf("[db-updater] Database file changed: checksum %s -> %s",
				diagBefore.DBChecksum, diagAfter.DBChecksum)
		} else if diagBefore.DBSize != diagAfter.DBSize {
			log.Printf("[db-updater] Database size changed: %d -> %d bytes",
				diagBefore.DBSize, diagAfter.DBSize)
		}
	}

	// Check for metadata mismatch (URL timestamp vs reported Built time)
	du.detectMetadataMismatch(dbStatus.Built, diagAfter)

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

// grypeImportJSON represents the structure of grype's import.json file
type grypeImportJSON struct {
	Digest        string `json:"digest"`
	Source        string `json:"source"`
	ClientVersion string `json:"client_version"`
}

// dbDiagnostics holds diagnostic information about the database state
type dbDiagnostics struct {
	DBPath       string
	DBSize       int64
	DBModTime    time.Time
	DBChecksum   string // First 16 chars of SHA256
	ImportJSON   *grypeImportJSON
	URLTimestamp string // Timestamp extracted from source URL
	URLChecksum  string // Checksum from source URL query param
}

// logDatabaseDiagnostics logs detailed information about the grype database state
// This helps diagnose issues where grype reports stale metadata after updates
func (du *DatabaseUpdater) logDatabaseDiagnostics(prefix string) *dbDiagnostics {
	grypeDir := filepath.Join(du.dbRootDir, "grype")
	diag := &dbDiagnostics{}

	// Find the schema version directory (e.g., "6")
	entries, err := os.ReadDir(grypeDir)
	if err != nil {
		log.Printf("[db-updater] %s: Cannot read grype dir: %v", prefix, err)
		return diag
	}

	var schemaDir string
	for _, entry := range entries {
		if entry.IsDir() {
			schemaDir = filepath.Join(grypeDir, entry.Name())
			break
		}
	}
	if schemaDir == "" {
		log.Printf("[db-updater] %s: No schema directory found", prefix)
		return diag
	}

	// Check vulnerability.db
	dbPath := filepath.Join(schemaDir, "vulnerability.db")
	diag.DBPath = dbPath
	if info, err := os.Stat(dbPath); err == nil {
		diag.DBSize = info.Size()
		diag.DBModTime = info.ModTime()

		// Calculate partial checksum (first 16 chars of SHA256)
		if f, err := os.Open(dbPath); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				diag.DBChecksum = hex.EncodeToString(h.Sum(nil))[:16]
			}
			f.Close()
		}
	}

	// Read import.json
	importPath := filepath.Join(schemaDir, "import.json")
	if data, err := os.ReadFile(importPath); err == nil {
		var importJSON grypeImportJSON
		if err := json.Unmarshal(data, &importJSON); err == nil {
			diag.ImportJSON = &importJSON

			// Extract timestamp from source URL (e.g., "2026-01-07T00:25:57Z" from the URL)
			tsRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
			if matches := tsRegex.FindStringSubmatch(importJSON.Source); len(matches) > 0 {
				diag.URLTimestamp = matches[0]
			}

			// Extract checksum from URL query param
			checksumRegex := regexp.MustCompile(`checksum=sha256%3A([a-f0-9]+)`)
			if matches := checksumRegex.FindStringSubmatch(importJSON.Source); len(matches) > 1 {
				diag.URLChecksum = matches[1][:16] // First 16 chars
			}
		}
	}

	// Log the diagnostics
	log.Printf("[db-updater] %s: db_size=%d, db_mod=%s, db_checksum=%s",
		prefix,
		diag.DBSize,
		diag.DBModTime.Format(time.RFC3339),
		diag.DBChecksum)

	if diag.ImportJSON != nil {
		log.Printf("[db-updater] %s: import_digest=%s, url_timestamp=%s, url_checksum=%s",
			prefix,
			diag.ImportJSON.Digest,
			diag.URLTimestamp,
			diag.URLChecksum)
	}

	return diag
}

// detectMetadataMismatch checks if there's a mismatch between grype's reported Built time
// and what we'd expect based on the import.json URL timestamp
func (du *DatabaseUpdater) detectMetadataMismatch(reportedBuilt time.Time, diag *dbDiagnostics) {
	if diag == nil || diag.URLTimestamp == "" {
		return
	}

	// Parse URL timestamp
	urlTime, err := time.Parse(time.RFC3339, diag.URLTimestamp)
	if err != nil {
		return
	}

	// The URL timestamp is when the archive was created
	// The Built timestamp should be on the same day or later
	// If Built is from a previous day, something is wrong
	urlDay := urlTime.Truncate(24 * time.Hour)
	builtDay := reportedBuilt.Truncate(24 * time.Hour)

	if builtDay.Before(urlDay) {
		log.Printf("[db-updater] WARNING: Metadata mismatch detected!")
		log.Printf("[db-updater]   URL timestamp: %s (archive from %s)",
			diag.URLTimestamp, urlDay.Format("2006-01-02"))
		log.Printf("[db-updater]   Reported Built: %s (from %s)",
			reportedBuilt.Format(time.RFC3339), builtDay.Format("2006-01-02"))
		log.Printf("[db-updater]   This may indicate grype returned stale metadata")
	}
}
