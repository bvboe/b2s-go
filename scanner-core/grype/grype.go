package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
)

// Config holds configuration for the Grype scanner
type Config struct {
	// DBRootDir is the root directory where Grype stores its vulnerability database
	// If empty, uses the default location (~/.cache/grype/db)
	DBRootDir string
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

	// Load the database with auto-update enabled
	log.Printf("Loading vulnerability database (will download if missing)...")
	vulnProvider, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	if err != nil {
		log.Printf("Failed to load vulnerability database: %v", err)
		if dbStatus != nil {
			log.Printf("Database status: Built=%v, SchemaVersion=%s, From=%s, Path=%s, Error=%v",
				dbStatus.Built, dbStatus.SchemaVersion, dbStatus.From, dbStatus.Path, dbStatus.Error)
		}
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	log.Printf("Loaded vulnerability database successfully")
	if dbStatus != nil {
		log.Printf("Database status: Built=%v, SchemaVersion=%s, From=%s",
			dbStatus.Built, dbStatus.SchemaVersion, dbStatus.From)
	}

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
	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
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
