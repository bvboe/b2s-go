package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
)

// SyftPackage represents a package from Syft SBOM
// We store the complete raw JSON to preserve ALL fields (current and future) and original field order
type SyftPackage struct {
	Name    string          `json:"-"` // Extracted for indexing, not marshaled
	Version string          `json:"-"` // Extracted for indexing, not marshaled
	Type    string          `json:"-"` // Extracted for indexing, not marshaled
	Raw     json.RawMessage `json:"-"` // Complete raw JSON with original field order
}

// UnmarshalJSON implements custom unmarshaling to extract index fields and preserve raw JSON
func (p *SyftPackage) UnmarshalJSON(data []byte) error {
	// Store the complete raw JSON (preserves all fields and original order)
	p.Raw = json.RawMessage(data)

	// Extract only the fields we need for indexing (name/version/type)
	var temp struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	p.Name = temp.Name
	p.Version = temp.Version
	p.Type = temp.Type
	return nil
}

// MarshalJSON returns the raw JSON (preserving all fields and original order)
// Uses value receiver so it works when marshaling []SyftPackage (not just []*SyftPackage)
func (p SyftPackage) MarshalJSON() ([]byte, error) {
	return p.Raw, nil
}

// SyftImageConfig represents the image configuration from Syft SBOM
type SyftImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// SyftImageTarget represents the target image metadata from Syft SBOM
type SyftImageTarget struct {
	Config SyftImageConfig `json:"config"`
}

// SyftSource represents the source metadata from Syft SBOM
type SyftSource struct {
	Type   string          `json:"type"`
	Target SyftImageTarget `json:"target"`
}

// SyftSBOM represents a Syft SBOM document
type SyftSBOM struct {
	Artifacts []SyftPackage `json:"artifacts"`
	Source    SyftSource    `json:"source"`
}

// GrypeMatch represents a vulnerability match from Grype
// We store the complete raw JSON to preserve ALL fields (current and future) and original field order
type GrypeMatch struct {
	// Fields extracted for indexing (not marshaled back)
	Vulnerability GrypeVulnerability `json:"-"`
	Artifact      GrypeArtifact      `json:"-"`

	// Complete raw JSON with original field order
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON implements custom unmarshaling to extract index fields and preserve raw JSON
func (m *GrypeMatch) UnmarshalJSON(data []byte) error {
	// Store the complete raw JSON (preserves all fields and original order)
	m.Raw = json.RawMessage(data)

	// Extract only the fields we need for indexing
	var temp struct {
		Vulnerability GrypeVulnerability `json:"vulnerability"`
		Artifact      GrypeArtifact      `json:"artifact"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	m.Vulnerability = temp.Vulnerability
	m.Artifact = temp.Artifact
	return nil
}

// MarshalJSON returns the raw JSON (preserving all fields and original order)
// Uses value receiver so it works when marshaling []GrypeMatch (not just []*GrypeMatch)
func (m GrypeMatch) MarshalJSON() ([]byte, error) {
	return m.Raw, nil
}

// GrypeArtifact represents the artifact (package) that has a vulnerability
type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GrypeVulnerability represents vulnerability details
type GrypeVulnerability struct {
	ID             string              `json:"id"`
	Severity       string              `json:"severity"`
	Fix            GrypeFix            `json:"fix"`
	Risk           float64             `json:"risk"`
	EPSS           []GrypeEPSS         `json:"epss"`
	KnownExploited []GrypeKnownExploit `json:"knownExploited"`
}

// GrypeEPSS represents EPSS (Exploit Prediction Scoring System) data
type GrypeEPSS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// GrypeKnownExploit represents known exploit information from CISA KEV
type GrypeKnownExploit struct {
	CVE                        string   `json:"cve"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	DateAdded                  string   `json:"dateAdded"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	URLs                       []string `json:"urls"`
	CWEs                       []string `json:"cwes"`
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
	Type       string          `json:"type"`
	Found      GrypeFound      `json:"found"`
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

// GrypeDistro represents distribution information from Grype
type GrypeDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// GrypeDocument represents a Grype vulnerability scan document
type GrypeDocument struct {
	Matches []GrypeMatch `json:"matches"`
	Distro  *GrypeDistro `json:"distro"`
}

// parseSBOMData parses SBOM JSON and populates packages table
func parseSBOMData(conn *sql.DB, imageID int64, sbomJSON []byte) error {
	var sbom SyftSBOM
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to unmarshal SBOM: %w", err)
	}

	// Count packages by name+version+type
	packageCounts := make(map[string]int)
	packageInfo := make(map[string][]SyftPackage) // Changed to store ALL packages, not just first

	for _, pkg := range sbom.Artifacts {
		key := fmt.Sprintf("%s|%s|%s", pkg.Name, pkg.Version, pkg.Type)
		packageCounts[key]++
		// Store ALL complete package data for this key
		packageInfo[key] = append(packageInfo[key], pkg)
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

	// Prepare statement for package details
	detailsStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO package_details (package_id, details)
		VALUES (?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare details statement: %w", err)
	}
	defer func() {
		if err := detailsStmt.Close(); err != nil {
			log.Printf("Warning: Failed to close details statement: %v", err)
		}
	}()

	totalPackages := 0
	for key, count := range packageCounts {
		packages := packageInfo[key]
		if len(packages) == 0 {
			log.Printf("Warning: No packages found for key %s", key)
			continue
		}

		// Use first package for summary data (they should all be identical for the same key)
		firstPkg := packages[0]

		result, err := stmt.Exec(imageID, firstPkg.Name, firstPkg.Version, firstPkg.Type, count)
		if err != nil {
			log.Printf("Warning: Failed to insert package %s: %v", firstPkg.Name, err)
			continue
		}

		// Get the package ID (either newly inserted or existing)
		packageID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Warning: Failed to get package ID for %s: %v", firstPkg.Name, err)
			continue
		}

		// Marshal ALL package instances to JSON with COMPLETE data
		// This ensures we capture all instances when count > 1 AND preserve all SBOM fields
		// Using struct marshaling preserves field order as defined in the struct
		detailsJSON, err := json.Marshal(packages)
		if err != nil {
			log.Printf("Warning: Failed to marshal package details for %s: %v", firstPkg.Name, err)
			continue
		}

		// Insert package details
		if _, err := detailsStmt.Exec(packageID, string(detailsJSON)); err != nil {
			log.Printf("Warning: Failed to insert package details for %s: %v", firstPkg.Name, err)
			// Continue anyway - the package itself was inserted
		}

		totalPackages++
	}

	// Update container_images with architecture information if available
	if sbom.Source.Target.Config.Architecture != "" {
		arch := sbom.Source.Target.Config.Architecture
		log.Printf("Extracted architecture info for image_id=%d: %s", imageID, arch)

		_, err = tx.Exec(`
			UPDATE container_images
			SET architecture = ?
			WHERE id = ?
		`, arch, imageID)
		if err != nil {
			log.Printf("Warning: Failed to update container_images with architecture info: %v", err)
		}
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
	vulnInfo := make(map[vulnKey][]GrypeMatch) // Changed to store ALL matches, not just first

	for _, match := range doc.Matches {
		// Get package info from artifact field
		key := vulnKey{
			cveID:          match.Vulnerability.ID,
			packageName:    match.Artifact.Name,
			packageVersion: match.Artifact.Version,
			packageType:    match.Artifact.Type,
		}

		vulnCounts[key]++
		// Store ALL matches for this vulnerability, not just the first one
		vulnInfo[key] = append(vulnInfo[key], match)
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
		 severity, fix_status, fixed_version, count,
		 risk, epss_score, epss_percentile, known_exploited)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("Warning: Failed to close statement: %v", err)
		}
	}()

	// Prepare statement for vulnerability details
	detailsStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO vulnerability_details (vulnerability_id, details)
		VALUES (?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare details statement: %w", err)
	}
	defer func() {
		if err := detailsStmt.Close(); err != nil {
			log.Printf("Warning: Failed to close details statement: %v", err)
		}
	}()

	totalVulns := 0
	for key, count := range vulnCounts {
		matches := vulnInfo[key]
		if len(matches) == 0 {
			log.Printf("Warning: No matches found for vulnerability %s", key.cveID)
			continue
		}

		log.Printf("[DEBUG] Processing vulnerability %s for package %s: count=%d, matches in array=%d",
			key.cveID, key.packageName, count, len(matches))

		// Use first match for summary data (they should all be identical for the same vulnerability)
		firstMatch := matches[0]

		// Determine fix status and version
		fixStatus := firstMatch.Vulnerability.Fix.State
		if fixStatus == "" {
			if len(firstMatch.Vulnerability.Fix.Versions) > 0 {
				fixStatus = "fixed"
			} else {
				fixStatus = "not-fixed"
			}
		}

		fixedVersion := ""
		if len(firstMatch.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = firstMatch.Vulnerability.Fix.Versions[0]
		}

		// Extract risk score
		risk := firstMatch.Vulnerability.Risk

		// Extract EPSS data (use first entry if available)
		epssScore := 0.0
		epssPercentile := 0.0
		if len(firstMatch.Vulnerability.EPSS) > 0 {
			epssScore = firstMatch.Vulnerability.EPSS[0].Score
			epssPercentile = firstMatch.Vulnerability.EPSS[0].Percentile
		}

		// Count known exploits from CISA KEV catalog
		knownExploited := len(firstMatch.Vulnerability.KnownExploited)

		result, err := stmt.Exec(
			imageID,
			key.cveID,
			key.packageName,
			key.packageVersion,
			key.packageType,
			firstMatch.Vulnerability.Severity,
			fixStatus,
			fixedVersion,
			count,
			risk,
			epssScore,
			epssPercentile,
			knownExploited,
		)
		if err != nil {
			log.Printf("Warning: Failed to insert vulnerability %s: %v", key.cveID, err)
			continue
		}

		// Get the vulnerability ID (either newly inserted or existing)
		vulnID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Warning: Failed to get vulnerability ID for %s: %v", key.cveID, err)
			continue
		}

		// Marshal ALL vulnerability matches to JSON (not just the first one)
		// This ensures we capture all instances when count > 1
		detailsJSON, err := json.Marshal(matches)
		if err != nil {
			log.Printf("Warning: Failed to marshal vulnerability details for %s: %v", key.cveID, err)
			continue
		}

		log.Printf("[DEBUG] Storing details for %s (vuln_id=%d): %d matches, JSON size=%d bytes",
			key.cveID, vulnID, len(matches), len(detailsJSON))

		// Insert vulnerability details
		if _, err := detailsStmt.Exec(vulnID, string(detailsJSON)); err != nil {
			log.Printf("Warning: Failed to insert vulnerability details for %s: %v", key.cveID, err)
			// Continue anyway - the vulnerability itself was inserted
		}

		totalVulns++
	}

	// Update container_images with distro information if available
	if doc.Distro != nil {
		osName := doc.Distro.Name
		osVersion := doc.Distro.Version
		log.Printf("Extracted distro info for image_id=%d: %s %s", imageID, osName, osVersion)

		_, err = tx.Exec(`
			UPDATE container_images
			SET os_name = ?, os_version = ?
			WHERE id = ?
		`, osName, osVersion, imageID)
		if err != nil {
			log.Printf("Warning: Failed to update container_images with distro info: %v", err)
		}
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
