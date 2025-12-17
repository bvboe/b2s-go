package grype

import (
	"bytes"
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
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/format/syftjson"
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

	// Parse the SBOM from JSON
	decoder := syftjson.NewFormatDecoder()
	s, _, _, err := decoder.Decode(bytes.NewReader(sbomJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to decode SBOM: %w", err)
	}

	if s == nil {
		return nil, fmt.Errorf("decoded SBOM is nil")
	}

	log.Printf("Decoded SBOM with %d packages", s.Artifacts.Packages.PackageCount())

	// Configure the vulnerability database location
	// Use DefaultConfig to get proper settings like LatestURL
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
	// This will automatically download the database if it doesn't exist
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

	// Convert SBOM packages to Grype packages
	packages := grypePkg.FromCollection(s.Artifacts.Packages, grypePkg.SynthesisConfig{})
	context := grypePkg.Context{
		Source: &s.Source,
		Distro: nil, // Distro conversion not needed for basic scanning
	}

	log.Printf("Scanning %d packages for vulnerabilities...", len(packages))

	// Create vulnerability matcher
	matcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
	}

	// Find vulnerability matches
	remainingMatches, ignoredMatches, err := matcher.FindMatches(packages, context)
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
