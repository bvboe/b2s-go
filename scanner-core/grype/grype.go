package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
)

// Config holds configuration for the Grype scanner
type Config struct {
	// DBRootDir is the root directory where Grype stores its vulnerability database
	// If empty, uses the default location (~/.cache/grype/db)
	DBRootDir string
}

// logDirectoryContents logs the contents of a directory for debugging
func logDirectoryContents(dir string, prefix string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("%s Directory does not exist: %s", prefix, dir)
		} else {
			log.Printf("%s Error reading directory %s: %v", prefix, dir, err)
		}
		return
	}

	if len(entries) == 0 {
		log.Printf("%s Directory is empty: %s", prefix, dir)
		return
	}

	log.Printf("%s Directory %s contains %d entries:", prefix, dir, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			log.Printf("%s   - %s (error getting info: %v)", prefix, entry.Name(), err)
			continue
		}
		if info.IsDir() {
			log.Printf("%s   - %s/ (directory)", prefix, entry.Name())
		} else {
			log.Printf("%s   - %s (%d bytes)", prefix, entry.Name(), info.Size())
		}
	}
}

// DatabaseStatus represents the current state of the vulnerability database
type DatabaseStatus struct {
	Available     bool      `json:"available"`
	Built         time.Time `json:"built,omitempty"`
	SchemaVersion string    `json:"schema_version,omitempty"`
	Path          string    `json:"path,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// InitializeDatabase ensures the vulnerability database is downloaded and ready.
// This should be called at startup before accepting scan requests.
// Returns the database status and any error encountered.
func InitializeDatabase(cfg Config) (*DatabaseStatus, error) {
	log.Printf("[grype-init] Initializing vulnerability database...")

	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification

	installCfg := installation.DefaultConfig(identification)

	if cfg.DBRootDir != "" {
		dbDir := filepath.Join(cfg.DBRootDir, "grype")
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return &DatabaseStatus{Available: false, Error: err.Error()},
				fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
		installCfg.DBRootDir = dbDir
		log.Printf("[grype-init] Using database directory: %s", dbDir)
	}

	// Log directory contents before initialization
	logDirectoryContents(installCfg.DBRootDir, "[grype-init-pre]")

	log.Printf("[grype-init] Loading/downloading vulnerability database...")
	startTime := time.Now()

	// Progress indicator
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				log.Printf("[grype-init] Still initializing database... (%v elapsed)", elapsed)
			}
		}
	}()

	_, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	close(done)

	loadDuration := time.Since(startTime).Round(time.Millisecond)

	if err != nil {
		log.Printf("[grype-init] Failed to initialize database after %v: %v", loadDuration, err)
		logDirectoryContents(installCfg.DBRootDir, "[grype-init-fail]")

		status := &DatabaseStatus{Available: false, Error: err.Error()}
		if dbStatus != nil {
			status.Path = dbStatus.Path
		}
		return status, fmt.Errorf("failed to initialize vulnerability database: %w", err)
	}

	log.Printf("[grype-init] Database initialized successfully in %v", loadDuration)
	logDirectoryContents(installCfg.DBRootDir, "[grype-init-post]")

	status := &DatabaseStatus{
		Available:     true,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
		Built:         dbStatus.Built,
	}

	log.Printf("[grype-init] Database ready: schema=%s, built=%v", status.SchemaVersion, status.Built)
	return status, nil
}

// CheckDatabase verifies the vulnerability database is available and valid.
// This is a lightweight check suitable for readiness probes.
func CheckDatabase(cfg Config) (*DatabaseStatus, error) {
	dbDir := cfg.DBRootDir
	if dbDir != "" {
		dbDir = filepath.Join(dbDir, "grype")
	} else {
		// Default grype location
		homeDir, _ := os.UserHomeDir()
		dbDir = filepath.Join(homeDir, ".cache", "grype", "db")
	}

	// Check if the database directory exists and has files
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &DatabaseStatus{Available: false, Error: "database directory does not exist"}, nil
		}
		return &DatabaseStatus{Available: false, Error: err.Error()}, err
	}

	if len(entries) == 0 {
		return &DatabaseStatus{Available: false, Error: "database directory is empty"}, nil
	}

	// Look for the vulnerability database file
	hasDB := false
	for _, entry := range entries {
		if entry.Name() == "vulnerability.db" || entry.Name() == "vulnerability-db" {
			hasDB = true
			break
		}
		// v6 uses a different structure - check for any .db file
		if filepath.Ext(entry.Name()) == ".db" {
			hasDB = true
			break
		}
	}

	if !hasDB {
		return &DatabaseStatus{Available: false, Error: "no database file found", Path: dbDir}, nil
	}

	return &DatabaseStatus{Available: true, Path: dbDir}, nil
}

// DeleteDatabase removes the vulnerability database, forcing a re-download on next use.
// This is useful for testing database initialization.
func DeleteDatabase(cfg Config) error {
	dbDir := cfg.DBRootDir
	if dbDir != "" {
		dbDir = filepath.Join(dbDir, "grype")
	} else {
		homeDir, _ := os.UserHomeDir()
		dbDir = filepath.Join(homeDir, ".cache", "grype", "db")
	}

	log.Printf("[grype-db] Deleting database directory: %s", dbDir)

	// Log contents before deletion
	logDirectoryContents(dbDir, "[grype-db-delete-pre]")

	if err := os.RemoveAll(dbDir); err != nil {
		return fmt.Errorf("failed to delete database directory: %w", err)
	}

	log.Printf("[grype-db] Database directory deleted successfully")
	return nil
}

// DefaultMatcherConfig returns the default matcher configuration that aligns with Grype CLI defaults
// This configuration is based on Grype v0.104.2 defaults and should be updated when Grype is upgraded
//
// Reference: https://github.com/anchore/grype
// To check current Grype defaults, run: grype <image> -o json | jq .descriptor.configuration.match
func DefaultMatcherConfig() matcher.Config {
	return matcher.Config{
		// Golang configuration - Critical for Go applications
		Golang: golang.MatcherConfig{
			UseCPEs: false, // Use direct matching via PURLs for Go modules
			// CRITICAL: Enable CPE matching for Go stdlib to catch standard library CVEs
			// Without this, stdlib vulnerabilities (often High/Critical severity) are missed
			AlwaysUseCPEForStdlib:                  true,
			AllowMainModulePseudoVersionComparison: false,
		},
		// Stock configuration - Generic package matching
		Stock: stock.MatcherConfig{
			UseCPEs: true, // Use CPE matching for packages without language-specific matchers
		},
		// Language-specific matchers - Use native package matching (not CPEs) by default
		// These rely on package URLs (PURLs) and native version comparisons which are more accurate
		Java: java.MatcherConfig{
			UseCPEs: false,
			ExternalSearchConfig: java.ExternalSearchConfig{
				SearchMavenUpstream: false, // Disabled by default - enable if needed for unknown Java deps
			},
		},
		Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
		Javascript: javascript.MatcherConfig{UseCPEs: false},
		Python:     python.MatcherConfig{UseCPEs: false},
		Ruby:       ruby.MatcherConfig{UseCPEs: false},
		Rust:       rust.MatcherConfig{UseCPEs: false},
	}
}

// ScanVulnerabilities scans an SBOM for vulnerabilities using Grype library
// Takes SBOM JSON bytes as input and returns vulnerability report as JSON bytes
func ScanVulnerabilities(ctx context.Context, sbomJSON []byte) ([]byte, error) {
	return ScanVulnerabilitiesWithConfig(ctx, sbomJSON, Config{})
}

// ScanVulnerabilitiesWithConfig scans an SBOM for vulnerabilities using Grype library with custom configuration
func ScanVulnerabilitiesWithConfig(ctx context.Context, sbomJSON []byte, cfg Config) ([]byte, error) {
	log.Printf("Starting vulnerability scan on SBOM (%d bytes)", len(sbomJSON))

	// Write SBOM to temp file so we can use Grype's Provide function
	// This ensures we get all the proper processing (distro, relationships, etc.)
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()
	defer func() {
		_ = tmpFile.Close()
	}()

	if _, err := tmpFile.Write(sbomJSON); err != nil {
		return nil, fmt.Errorf("failed to write SBOM to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	log.Printf("Using Grype's SBOM provider for complete processing")

	// Configure the vulnerability database location
	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification

	installCfg := installation.DefaultConfig(identification)

	if cfg.DBRootDir != "" {
		// Ensure the directory exists
		dbDir := filepath.Join(cfg.DBRootDir, "grype")
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
		installCfg.DBRootDir = dbDir
		log.Printf("Using Grype database directory: %s", dbDir)
	}

	// Check if database exists, if not download it
	log.Printf("Checking vulnerability database status...")
	log.Printf("Database config: DBRootDir=%s, LatestURL=%s", installCfg.DBRootDir, distCfg.LatestURL)

	// Log directory contents before loading (helps diagnose issues)
	logDirectoryContents(installCfg.DBRootDir, "[grype-db-pre]")

	// Load the database with auto-update enabled, with progress logging
	log.Printf("Loading vulnerability database (will download if missing)...")
	startTime := time.Now()

	// Start a progress indicator goroutine
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				log.Printf("[grype-db] Still loading database... (%v elapsed)", elapsed)
			}
		}
	}()

	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	close(done) // Stop progress indicator

	loadDuration := time.Since(startTime).Round(time.Millisecond)

	if err != nil {
		log.Printf("Failed to load vulnerability database after %v: %v", loadDuration, err)
		if dbStatus != nil {
			log.Printf("Database status: Built=%v, SchemaVersion=%s, From=%s, Path=%s, Error=%v",
				dbStatus.Built, dbStatus.SchemaVersion, dbStatus.From, dbStatus.Path, dbStatus.Error)
		}
		// Log directory contents after failure to see what state we're in
		logDirectoryContents(installCfg.DBRootDir, "[grype-db-post-fail]")
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	log.Printf("Loaded vulnerability database successfully in %v", loadDuration)
	if dbStatus != nil {
		log.Printf("Database status: Built=%v, SchemaVersion=%s, From=%s",
			dbStatus.Built, dbStatus.SchemaVersion, dbStatus.From)
	}

	// Log directory contents after successful load
	logDirectoryContents(installCfg.DBRootDir, "[grype-db-post]")

	// Use Grype's Provide function to get packages and context with proper processing
	// This handles distro extraction, relationship processing, and package filtering
	providerConfig := grypePkg.ProviderConfig{}
	packages, context, _, err := grypePkg.Provide("sbom:"+tmpFile.Name(), providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to provide packages from SBOM: %w", err)
	}

	log.Printf("Scanning %d packages for vulnerabilities...", len(packages))
	if len(packages) > 0 {
		log.Printf("Sample package PURL: %s", packages[0].PURL)
		if context.Distro != nil {
			log.Printf("Context distro: %s", context.Distro.String())
		}
	}

	// Create vulnerability matcher with all default matchers (dpkg, rpm, apk, etc.)
	// Use DefaultMatcherConfig() to ensure we match Grype CLI defaults
	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matcher.NewDefaultMatchers(DefaultMatcherConfig()),
	}

	// Find vulnerability matches
	remainingMatches, ignoredMatches, err := vulnerabilityMatcher.FindMatches(packages, context)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	if remainingMatches == nil {
		return nil, fmt.Errorf("vulnerability matches are nil")
	}

	log.Printf("Found %d vulnerability matches (%d ignored)", remainingMatches.Count(), len(ignoredMatches))

	// Build the output document using NewDocument
	doc, err := models.NewDocument(
		identification,         // clio.Identification
		packages,               // packages
		context,                // context
		*remainingMatches,      // matches
		ignoredMatches,         // ignoredMatches
		vulnProvider,           // metadataProvider
		nil,                    // appConfig
		nil,                    // dbInfo
		models.SortBySeverity,  // sortStrategy
		false,                  // outputTimestamp
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	// Encode to JSON
	reportJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode vulnerability report to JSON: %w", err)
	}

	log.Printf("Vulnerability scan complete (%d bytes)", len(reportJSON))

	return reportJSON, nil
}
