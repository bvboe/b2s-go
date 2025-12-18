package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
)

// SyftPackage represents a package from Syft SBOM
type SyftPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// SyftSBOM represents a Syft SBOM document
type SyftSBOM struct {
	Artifacts []SyftPackage `json:"artifacts"`
}

// GrypeMatch represents a vulnerability match from Grype
type GrypeMatch struct {
	Vulnerability          GrypeVulnerability `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVuln `json:"relatedVulnerabilities"`
	MatchDetails           []GrypeMatchDetail `json:"matchDetails"`
	Artifact               GrypeArtifact      `json:"artifact"`
}

// GrypeArtifact represents the artifact (package) that has a vulnerability
type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GrypeVulnerability represents vulnerability details
type GrypeVulnerability struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Fix      GrypeFix `json:"fix"`
	Risk     float64  `json:"risk"`
}

// GrypeRelatedVuln represents related vulnerabilities
type GrypeRelatedVuln struct {
	ID string `json:"id"`
}

// GrypeFix represents fix information
type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

// GrypeMatchDetail represents match details
type GrypeMatchDetail struct {
	Type   string        `json:"type"`
	Found  GrypeFound    `json:"found"`
	SearchedBy GrypeSearchedBy `json:"searchedBy"`
}

// GrypeFound represents what was found
type GrypeFound struct {
	VersionConstraint string `json:"versionConstraint"`
}

// GrypeSearchedBy represents search criteria
type GrypeSearchedBy struct {
	Package GrypePackageInfo `json:"package"`
}

// GrypePackageInfo represents package information
type GrypePackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GrypeDocument represents a Grype vulnerability scan document
type GrypeDocument struct {
	Matches []GrypeMatch `json:"matches"`
}

// parseSBOMData parses SBOM JSON and populates packages and image_summary tables
func parseSBOMData(conn *sql.DB, imageID int64, sbomJSON []byte) error {
	var sbom SyftSBOM
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to unmarshal SBOM: %w", err)
	}

	// Count packages by name+version+type
	packageCounts := make(map[string]int)
	packageInfo := make(map[string]SyftPackage)

	for _, pkg := range sbom.Artifacts {
		key := fmt.Sprintf("%s|%s|%s", pkg.Name, pkg.Version, pkg.Type)
		packageCounts[key]++
		if _, exists := packageInfo[key]; !exists {
			packageInfo[key] = pkg
		}
	}

	// Insert packages into database
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO packages (image_id, name, version, type, number_of_instances)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("Warning: Failed to close statement: %v", err)
		}
	}()

	totalPackages := 0
	for key, count := range packageCounts {
		pkg := packageInfo[key]
		if _, err := stmt.Exec(imageID, pkg.Name, pkg.Version, pkg.Type, count); err != nil {
			log.Printf("Warning: Failed to insert package %s: %v", pkg.Name, err)
			continue
		}
		totalPackages++
	}

	// Update image_summary (OS info can be extracted from distro field in vulnerability scan or left empty)
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO image_summary (image_id, package_count, os_name, os_version, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, imageID, totalPackages, "", "")
	if err != nil {
		return fmt.Errorf("failed to update image_summary: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Parsed SBOM for image_id=%d: %d unique packages, %d total instances",
		imageID, totalPackages, len(sbom.Artifacts))
	return nil
}

// parseVulnerabilityData parses Grype vulnerability JSON and populates vulnerabilities table
func parseVulnerabilityData(conn *sql.DB, imageID int64, vulnJSON []byte) error {
	var doc GrypeDocument
	if err := json.Unmarshal(vulnJSON, &doc); err != nil {
		return fmt.Errorf("failed to unmarshal vulnerability data: %w", err)
	}

	// Group vulnerabilities by unique key
	type vulnKey struct {
		cveID          string
		packageName    string
		packageVersion string
		packageType    string
	}
	vulnCounts := make(map[vulnKey]int)
	vulnInfo := make(map[vulnKey]GrypeMatch)

	for _, match := range doc.Matches {
		// Get package info from artifact field
		key := vulnKey{
			cveID:          match.Vulnerability.ID,
			packageName:    match.Artifact.Name,
			packageVersion: match.Artifact.Version,
			packageType:    match.Artifact.Type,
		}

		vulnCounts[key]++
		if _, exists := vulnInfo[key]; !exists {
			vulnInfo[key] = match
		}
	}

	// Insert vulnerabilities into database
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO vulnerabilities
		(image_id, cve_id, package_name, package_version, package_type,
		 severity, fix_status, fixed_version, known_exploits, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("Warning: Failed to close statement: %v", err)
		}
	}()

	totalVulns := 0
	for key, count := range vulnCounts {
		match := vulnInfo[key]

		// Determine fix status and version
		fixStatus := match.Vulnerability.Fix.State
		if fixStatus == "" {
			if len(match.Vulnerability.Fix.Versions) > 0 {
				fixStatus = "fixed"
			} else {
				fixStatus = "not-fixed"
			}
		}

		fixedVersion := ""
		if len(match.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = match.Vulnerability.Fix.Versions[0]
		}

		// Count known exploits (related vulnerabilities with known exploits)
		knownExploits := len(match.RelatedVulnerabilities)

		_, err := stmt.Exec(
			imageID,
			key.cveID,
			key.packageName,
			key.packageVersion,
			key.packageType,
			match.Vulnerability.Severity,
			fixStatus,
			fixedVersion,
			knownExploits,
			count,
		)
		if err != nil {
			log.Printf("Warning: Failed to insert vulnerability %s: %v", key.cveID, err)
			continue
		}
		totalVulns++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Parsed vulnerabilities for image_id=%d: %d unique vulnerabilities", imageID, totalVulns)
	return nil
}

// ParseAndStoreImageData parses both SBOM and vulnerability data for an image
// This should be called whenever SBOM or vulnerability data is stored
func (db *DB) ParseAndStoreImageData(imageID int64) error {
	// Get SBOM and vulnerability data
	var sbomJSON, vulnJSON sql.NullString
	err := db.conn.QueryRow(`
		SELECT sbom, vulnerabilities
		FROM container_images
		WHERE id = ?
	`, imageID).Scan(&sbomJSON, &vulnJSON)
	if err != nil {
		return fmt.Errorf("failed to query image data: %w", err)
	}

	// Parse SBOM if available
	if sbomJSON.Valid && sbomJSON.String != "" {
		if err := parseSBOMData(db.conn, imageID, []byte(sbomJSON.String)); err != nil {
			return fmt.Errorf("failed to parse SBOM: %w", err)
		}
	}

	// Parse vulnerabilities if available
	if vulnJSON.Valid && vulnJSON.String != "" {
		if err := parseVulnerabilityData(db.conn, imageID, []byte(vulnJSON.String)); err != nil {
			return fmt.Errorf("failed to parse vulnerabilities: %w", err)
		}
	}

	return nil
}
