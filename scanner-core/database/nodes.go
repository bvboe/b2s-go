package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// NodeRow represents a node row from the database
type NodeRow struct {
	ID               int64
	Name             string
	Hostname         sql.NullString
	OSRelease        sql.NullString
	KernelVersion    sql.NullString
	Architecture     sql.NullString
	ContainerRuntime sql.NullString
	KubeletVersion   sql.NullString
	Status           sql.NullString
	StatusError      sql.NullString
	SBOMScannedAt    sql.NullTime
	VulnsScannedAt   sql.NullTime
	GrypeDBBuilt     sql.NullString
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// AddNode adds a new node to the database or returns existing
// Returns true if a new node was created, false if it already existed
func (db *DB) AddNode(n nodes.Node) (bool, error) {
	// Try to get existing node
	var existingID int64
	err := db.conn.QueryRow(`
		SELECT id FROM nodes WHERE name = ?
	`, n.Name).Scan(&existingID)

	if err == nil {
		// Node already exists, update it
		_, err = db.conn.Exec(`
			UPDATE nodes SET
				hostname = ?,
				os_release = ?,
				kernel_version = ?,
				architecture = ?,
				container_runtime = ?,
				kubelet_version = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE name = ?
		`, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture,
			n.ContainerRuntime, n.KubeletVersion, n.Name)
		if err != nil {
			return false, fmt.Errorf("failed to update node: %w", err)
		}
		return false, nil
	}

	if err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to query node: %w", err)
	}

	// Node doesn't exist, create it
	result, err := db.conn.Exec(`
		INSERT INTO nodes (name, hostname, os_release, kernel_version, architecture, container_runtime, kubelet_version, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
	`, n.Name, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture, n.ContainerRuntime, n.KubeletVersion)

	if err != nil {
		return false, fmt.Errorf("failed to insert node: %w", err)
	}

	id, _ := result.LastInsertId()
	log.Printf("New node added to database: %s (id=%d)", n.Name, id)
	return true, nil
}

// UpdateNode updates an existing node in the database
func (db *DB) UpdateNode(n nodes.Node) error {
	result, err := db.conn.Exec(`
		UPDATE nodes SET
			hostname = ?,
			os_release = ?,
			kernel_version = ?,
			architecture = ?,
			container_runtime = ?,
			kubelet_version = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE name = ?
	`, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture,
		n.ContainerRuntime, n.KubeletVersion, n.Name)
	if err != nil {
		return fmt.Errorf("failed to update node: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Node doesn't exist, add it
		_, err = db.AddNode(n)
		return err
	}

	return nil
}

// RemoveNode removes a node and all its associated data from the database
func (db *DB) RemoveNode(name string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get node ID
	var nodeID int64
	err = tx.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return nil // Node doesn't exist, nothing to do
	}
	if err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Delete node vulnerabilities
	_, err = tx.Exec(`DELETE FROM node_vulnerabilities WHERE node_id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete node vulnerabilities: %w", err)
	}

	// Delete node packages
	_, err = tx.Exec(`DELETE FROM node_packages WHERE node_id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete node packages: %w", err)
	}

	// Delete node
	_, err = tx.Exec(`DELETE FROM nodes WHERE id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete node: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Removed node from database: %s (id=%d)", name, nodeID)
	return nil
}

// GetNode retrieves a node with its scan status
func (db *DB) GetNode(name string) (*nodes.NodeWithStatus, error) {
	var row NodeRow
	err := db.conn.QueryRow(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at
		FROM nodes
		WHERE name = ?
	`, name).Scan(
		&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
		&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
		&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
		&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get node: %w", err)
	}

	return db.nodeRowToNodeWithStatus(&row)
}

// GetAllNodes retrieves all nodes with their scan status
func (db *DB) GetAllNodes() ([]nodes.NodeWithStatus, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at
		FROM nodes
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}

	// Collect all rows first before making additional queries
	// This avoids SQLite connection issues with nested queries
	var nodeRows []NodeRow
	for rows.Next() {
		var row NodeRow
		err := rows.Scan(
			&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
			&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
			&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
			&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
		)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		nodeRows = append(nodeRows, row)
	}
	_ = rows.Close()

	// Now convert rows to NodeWithStatus (which makes additional queries)
	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	result := make([]nodes.NodeWithStatus, 0, len(nodeRows))
	for _, row := range nodeRows {
		node, err := db.nodeRowToNodeWithStatus(&row)
		if err != nil {
			return nil, err
		}
		result = append(result, *node)
	}

	return result, nil
}

// nodeRowToNodeWithStatus converts a database row to a NodeWithStatus struct
func (db *DB) nodeRowToNodeWithStatus(row *NodeRow) (*nodes.NodeWithStatus, error) {
	node := &nodes.NodeWithStatus{
		Node: nodes.Node{
			Name: row.Name,
		},
		NodeScanStatus: nodes.NodeScanStatus{
			Status: "pending",
		},
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}

	if row.Hostname.Valid {
		node.Hostname = row.Hostname.String
	}
	if row.OSRelease.Valid {
		node.OSRelease = row.OSRelease.String
	}
	if row.KernelVersion.Valid {
		node.KernelVersion = row.KernelVersion.String
	}
	if row.Architecture.Valid {
		node.Architecture = row.Architecture.String
	}
	if row.ContainerRuntime.Valid {
		node.ContainerRuntime = row.ContainerRuntime.String
	}
	if row.KubeletVersion.Valid {
		node.KubeletVersion = row.KubeletVersion.String
	}
	if row.Status.Valid {
		node.Status = row.Status.String
	}
	if row.StatusError.Valid {
		node.StatusError = row.StatusError.String
	}
	if row.SBOMScannedAt.Valid {
		node.SBOMScannedAt = &row.SBOMScannedAt.Time
	}
	if row.VulnsScannedAt.Valid {
		node.VulnsScannedAt = &row.VulnsScannedAt.Time
	}
	if row.GrypeDBBuilt.Valid {
		t, _ := time.Parse(time.RFC3339, row.GrypeDBBuilt.String)
		node.GrypeDBBuilt = &t
	}

	// Get package count
	var pkgCount int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM node_packages WHERE node_id = ?
	`, row.ID).Scan(&pkgCount)
	if err == nil {
		node.PackageCount = pkgCount
	}

	// Get vulnerability count
	var vulnCount int
	err = db.conn.QueryRow(`
		SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = ?
	`, row.ID).Scan(&vulnCount)
	if err == nil {
		node.VulnerabilityCount = vulnCount
	}

	return node, nil
}

// GetNodeScanStatus returns the scan status for a node
func (db *DB) GetNodeScanStatus(name string) (string, error) {
	var status sql.NullString
	err := db.conn.QueryRow(`
		SELECT status FROM nodes WHERE name = ?
	`, name).Scan(&status)
	if err == sql.ErrNoRows {
		return "pending", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get node scan status: %w", err)
	}
	if !status.Valid {
		return "pending", nil
	}
	return status.String, nil
}

// IsNodeScanComplete checks if a node has complete scan data
func (db *DB) IsNodeScanComplete(name string) (bool, error) {
	var nodeID int64
	var status sql.NullString
	err := db.conn.QueryRow(`
		SELECT id, status FROM nodes WHERE name = ?
	`, name).Scan(&nodeID, &status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check node scan status: %w", err)
	}

	// Must be in completed status
	if !status.Valid || status.String != StatusCompleted.String() {
		return false, nil
	}

	// Must have packages (unless it's a very minimal node)
	var pkgCount int
	err = db.conn.QueryRow(`
		SELECT COUNT(*) FROM node_packages WHERE node_id = ?
	`, nodeID).Scan(&pkgCount)
	if err != nil {
		return false, fmt.Errorf("failed to count node packages: %w", err)
	}

	return pkgCount > 0, nil
}

// UpdateNodeStatus updates the scan status for a node
func (db *DB) UpdateNodeStatus(name string, status Status, errorMsg string) error {
	_, err := db.conn.Exec(`
		UPDATE nodes SET
			status = ?,
			status_error = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE name = ?
	`, status.String(), errorMsg, name)
	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}
	return nil
}

// StoreNodeSBOM stores the SBOM for a node and parses package data
func (db *DB) StoreNodeSBOM(name string, sbomJSON []byte) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get node ID
	var nodeID int64
	err = tx.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID)
	if err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Delete existing packages for this node
	_, err = tx.Exec(`DELETE FROM node_packages WHERE node_id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete existing packages: %w", err)
	}

	// Parse SBOM and insert packages
	// Syft JSON format has artifacts as a top-level array
	// Use json.RawMessage to preserve the full artifact JSON for details
	var sbom struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}

	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Group packages by (name, version, type) to count instances and collect details
	type packageKey struct {
		Name    string
		Version string
		Type    string
	}
	type packageData struct {
		Language  string
		PURL      string
		Instances []json.RawMessage
	}
	packageGroups := make(map[packageKey]*packageData)

	for _, artifactRaw := range sbom.Artifacts {
		var pkg struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		}
		if err := json.Unmarshal(artifactRaw, &pkg); err != nil {
			log.Printf("Warning: Failed to parse artifact: %v", err)
			continue
		}

		key := packageKey{Name: pkg.Name, Version: pkg.Version, Type: pkg.Type}
		if existing, ok := packageGroups[key]; ok {
			existing.Instances = append(existing.Instances, artifactRaw)
			// Keep first non-empty values for language/purl
			if existing.Language == "" && pkg.Language != "" {
				existing.Language = pkg.Language
			}
			if existing.PURL == "" && pkg.PURL != "" {
				existing.PURL = pkg.PURL
			}
		} else {
			packageGroups[key] = &packageData{
				Language:  pkg.Language,
				PURL:      pkg.PURL,
				Instances: []json.RawMessage{artifactRaw},
			}
		}
	}

	// Prepare statements for packages and details
	pkgStmt, err := tx.Prepare(`
		INSERT INTO node_packages (node_id, name, version, type, language, purl, number_of_instances)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (node_id, name, version, type) DO UPDATE SET
			language = excluded.language,
			purl = excluded.purl,
			number_of_instances = excluded.number_of_instances
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare package statement: %w", err)
	}
	defer func() { _ = pkgStmt.Close() }()

	detailsStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO node_package_details (node_package_id, details)
		VALUES (?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare details statement: %w", err)
	}
	defer func() { _ = detailsStmt.Close() }()

	// Insert packages and their details
	for key, data := range packageGroups {
		// Insert package (without details)
		result, err := pkgStmt.Exec(nodeID, key.Name, key.Version, key.Type, data.Language, data.PURL, len(data.Instances))
		if err != nil {
			return fmt.Errorf("failed to insert package: %w", err)
		}

		// Get package ID (either from insert or existing)
		var packageID int64
		packageID, err = result.LastInsertId()
		if err != nil || packageID == 0 {
			// ON CONFLICT happened, need to query for the ID
			err = tx.QueryRow(`SELECT id FROM node_packages WHERE node_id = ? AND name = ? AND version = ? AND type = ?`,
				nodeID, key.Name, key.Version, key.Type).Scan(&packageID)
			if err != nil {
				return fmt.Errorf("failed to get package ID: %w", err)
			}
		}

		// Serialize all instances as JSON array for details
		detailsJSON, err := json.Marshal(data.Instances)
		if err != nil {
			log.Printf("Warning: Failed to marshal package details for %s: %v", key.Name, err)
			detailsJSON = []byte("[]")
		}

		// Insert details into separate table
		_, err = detailsStmt.Exec(packageID, string(detailsJSON))
		if err != nil {
			return fmt.Errorf("failed to insert package details: %w", err)
		}
	}

	// Update node status
	_, err = tx.Exec(`
		UPDATE nodes SET
			status = ?,
			sbom_scanned_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StatusScanningVulnerabilities.String(), nodeID)
	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Stored SBOM for node %s: %d unique packages (%d total artifacts)", name, len(packageGroups), len(sbom.Artifacts))
	return nil
}

// StoreNodeVulnerabilities stores vulnerabilities for a node
// Groups duplicates and stores details in separate table
func (db *DB) StoreNodeVulnerabilities(name string, vulnJSON []byte, grypeDBBuilt time.Time) error {
	// Get node ID first (outside transaction)
	var nodeID int64
	err := db.conn.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID)
	if err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Parse vulnerability report using json.RawMessage to preserve full match details
	var report struct {
		Matches []json.RawMessage `json:"matches"`
	}

	if err := json.Unmarshal(vulnJSON, &report); err != nil {
		return fmt.Errorf("failed to parse vulnerability report: %w", err)
	}

	// Define a struct to parse just the fields we need from each match
	type parsedMatch struct {
		Raw           json.RawMessage
		Vulnerability struct {
			ID             string  `json:"id"`
			Severity       string  `json:"severity"`
			Risk           float64 `json:"risk"`
			KnownExploited []struct {
				CVE string `json:"cve"`
			} `json:"knownExploited"`
			Fix struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	}

	// Build a map of package name+version+type -> package ID for faster lookups
	packageMap := make(map[string]int64)
	rows, err := db.conn.Query(`SELECT id, name, version, type FROM node_packages WHERE node_id = ?`, nodeID)
	if err != nil {
		return fmt.Errorf("failed to query packages: %w", err)
	}
	for rows.Next() {
		var id int64
		var pkgName, version, pkgType string
		if err := rows.Scan(&id, &pkgName, &version, &pkgType); err != nil {
			_ = rows.Close()
			return fmt.Errorf("failed to scan package: %w", err)
		}
		key := pkgName + "|" + version + "|" + pkgType
		packageMap[key] = id
	}
	_ = rows.Close()

	// Group vulnerabilities by (package_id, cve_id) to deduplicate and aggregate details
	type vulnKey struct {
		PackageID int64
		CVEID     string
	}
	type vulnData struct {
		Severity       string
		Risk           float64
		FixStatus      string
		FixVersion     string
		KnownExploited int
		Instances      []json.RawMessage
	}
	vulnGroups := make(map[vulnKey]*vulnData)

	for _, matchRaw := range report.Matches {
		var pm parsedMatch
		if err := json.Unmarshal(matchRaw, &pm); err != nil {
			log.Printf("Warning: Failed to parse vulnerability match: %v", err)
			continue
		}
		pm.Raw = matchRaw

		// Look up package ID from map
		pkgKey := pm.Artifact.Name + "|" + pm.Artifact.Version + "|" + pm.Artifact.Type
		packageID, found := packageMap[pkgKey]
		if !found {
			// Package not found, skip this vulnerability
			continue
		}

		key := vulnKey{PackageID: packageID, CVEID: pm.Vulnerability.ID}
		if existing, ok := vulnGroups[key]; ok {
			// Aggregate: add to instances, keep max values
			existing.Instances = append(existing.Instances, matchRaw)
			if pm.Vulnerability.Risk > existing.Risk {
				existing.Risk = pm.Vulnerability.Risk
			}
			knownExploited := len(pm.Vulnerability.KnownExploited)
			if knownExploited > existing.KnownExploited {
				existing.KnownExploited = knownExploited
			}
		} else {
			fixVersion := ""
			if len(pm.Vulnerability.Fix.Versions) > 0 {
				fixVersion = pm.Vulnerability.Fix.Versions[0]
			}
			vulnGroups[key] = &vulnData{
				Severity:       pm.Vulnerability.Severity,
				Risk:           pm.Vulnerability.Risk,
				FixStatus:      pm.Vulnerability.Fix.State,
				FixVersion:     fixVersion,
				KnownExploited: len(pm.Vulnerability.KnownExploited),
				Instances:      []json.RawMessage{matchRaw},
			}
		}
	}

	// Delete existing vulnerabilities
	if _, err := db.conn.Exec(`DELETE FROM node_vulnerabilities WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("failed to delete existing vulnerabilities: %w", err)
	}

	// Insert unique vulnerabilities and their details
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	vulnStmt, err := tx.Prepare(`
		INSERT INTO node_vulnerabilities (node_id, package_id, cve_id, severity, score, fix_status, fix_version, known_exploited, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare vulnerability statement: %w", err)
	}
	defer func() { _ = vulnStmt.Close() }()

	detailsStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO node_vulnerability_details (node_vulnerability_id, details)
		VALUES (?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare details statement: %w", err)
	}
	defer func() { _ = detailsStmt.Close() }()

	totalInserted := 0
	for key, data := range vulnGroups {
		// Insert vulnerability (without details column)
		result, err := vulnStmt.Exec(nodeID, key.PackageID, key.CVEID, data.Severity, data.Risk, data.FixStatus, data.FixVersion, data.KnownExploited, len(data.Instances))
		if err != nil {
			log.Printf("Warning: failed to insert vulnerability %s: %v", key.CVEID, err)
			continue
		}

		vulnID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Warning: failed to get vulnerability ID for %s: %v", key.CVEID, err)
			continue
		}

		// Serialize all instances as JSON array for details
		detailsJSON, err := json.Marshal(data.Instances)
		if err != nil {
			log.Printf("Warning: Failed to marshal vulnerability details for %s: %v", key.CVEID, err)
			detailsJSON = []byte("[]")
		}

		// Insert details into separate table
		_, err = detailsStmt.Exec(vulnID, string(detailsJSON))
		if err != nil {
			log.Printf("Warning: failed to insert vulnerability details for %s: %v", key.CVEID, err)
		}

		totalInserted++
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Update node status
	_, err = db.conn.Exec(`
		UPDATE nodes SET
			status = ?,
			vulns_scanned_at = CURRENT_TIMESTAMP,
			grype_db_built = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StatusCompleted.String(), grypeDBBuilt.Format(time.RFC3339), nodeID)
	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}

	log.Printf("Stored vulnerabilities for node %s: %d unique (from %d matches)", name, totalInserted, len(report.Matches))
	return nil
}

// GetNodePackages retrieves all packages for a node with instance counts
func (db *DB) GetNodePackages(name string) ([]nodes.NodePackage, error) {
	rows, err := db.conn.Query(`
		SELECT np.id, np.node_id, np.name, np.version, np.type, np.language, np.purl,
			COALESCE(np.number_of_instances, 1) as count
		FROM node_packages np
		JOIN nodes n ON np.node_id = n.id
		WHERE n.name = ?
		ORDER BY np.name, np.version
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	packages := []nodes.NodePackage{} // Initialize to empty slice, not nil (JSON: [] not null)
	for rows.Next() {
		var pkg nodes.NodePackage
		var language, purl sql.NullString
		err := rows.Scan(&pkg.ID, &pkg.NodeID, &pkg.Name, &pkg.Version, &pkg.Type, &language, &purl, &pkg.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}
		if language.Valid {
			pkg.Language = language.String
		}
		if purl.Valid {
			pkg.PURL = purl.String
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetNodeVulnerabilities retrieves all vulnerabilities for a node with package info
func (db *DB) GetNodeVulnerabilities(name string) ([]nodes.NodeVulnerability, error) {
	rows, err := db.conn.Query(`
		SELECT nv.id, nv.node_id, nv.package_id, nv.cve_id, nv.severity, nv.score,
			nv.fix_status, nv.fix_version, nv.known_exploited, nv.created_at,
			np.name, np.version, np.type, COALESCE(nv.count, 1) as count
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		JOIN node_packages np ON nv.package_id = np.id
		WHERE n.name = ?
		ORDER BY
			CASE nv.severity
				WHEN 'Critical' THEN 1
				WHEN 'High' THEN 2
				WHEN 'Medium' THEN 3
				WHEN 'Low' THEN 4
				WHEN 'Negligible' THEN 5
				ELSE 6
			END ASC,
			nv.cve_id ASC
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	vulns := []nodes.NodeVulnerability{} // Initialize to empty slice, not nil (JSON: [] not null)
	for rows.Next() {
		var vuln nodes.NodeVulnerability
		var score sql.NullFloat64
		var fixStatus, fixVersion sql.NullString
		err := rows.Scan(&vuln.ID, &vuln.NodeID, &vuln.PackageID, &vuln.CVEID, &vuln.Severity, &score,
			&fixStatus, &fixVersion, &vuln.KnownExploited, &vuln.CreatedAt,
			&vuln.PackageName, &vuln.PackageVersion, &vuln.PackageType, &vuln.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		if score.Valid {
			vuln.Score = score.Float64
		}
		if fixStatus.Valid {
			vuln.FixStatus = fixStatus.String
		}
		if fixVersion.Valid {
			vuln.FixVersion = fixVersion.String
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// GetNodeVulnerabilityDetails returns the JSON details for a specific node vulnerability by ID
func (db *DB) GetNodeVulnerabilityDetails(id int64) (string, error) {
	var details sql.NullString
	err := db.conn.QueryRow(`
		SELECT details FROM node_vulnerability_details WHERE node_vulnerability_id = ?
	`, id).Scan(&details)
	if err == sql.ErrNoRows {
		return "[]", nil // Return empty JSON array if no details
	}
	if err != nil {
		return "", fmt.Errorf("failed to query vulnerability details: %w", err)
	}
	if !details.Valid || details.String == "" {
		return "[]", nil // Return empty JSON array if no details
	}
	return details.String, nil
}

// GetNodePackageDetails returns the JSON details for a specific node package by ID
func (db *DB) GetNodePackageDetails(id int64) (string, error) {
	var details sql.NullString
	err := db.conn.QueryRow(`
		SELECT details FROM node_package_details WHERE node_package_id = ?
	`, id).Scan(&details)
	if err == sql.ErrNoRows {
		return "[]", nil // Return empty JSON array if no details
	}
	if err != nil {
		return "", fmt.Errorf("failed to query package details: %w", err)
	}
	if !details.Valid || details.String == "" {
		return "[]", nil // Return empty JSON array if no details
	}
	return details.String, nil
}

// NodeSummaryFilters contains filter options for node summary queries
type NodeSummaryFilters struct {
	OSNames      []string // Filter by OS release names
	VulnStatuses []string // Filter vulnerabilities by fix_status (fixed, not-fixed, wont-fix, unknown)
	PackageTypes []string // Filter vulnerabilities by package type (deb, rpm, apk, etc.)
}

// GetNodeSummaries returns vulnerability summaries for all nodes (no filtering)
func (db *DB) GetNodeSummaries() ([]nodes.NodeSummary, error) {
	return db.GetNodeSummariesFiltered(NodeSummaryFilters{})
}

// GetNodeSummariesFiltered returns vulnerability summaries for nodes with optional filtering
func (db *DB) GetNodeSummariesFiltered(filters NodeSummaryFilters) ([]nodes.NodeSummary, error) {
	// Build the vulnerability filter clause for subqueries
	vulnFilter := ""
	var vulnFilterArgs []interface{}

	if len(filters.VulnStatuses) > 0 || len(filters.PackageTypes) > 0 {
		conditions := []string{}

		if len(filters.VulnStatuses) > 0 {
			placeholders := make([]string, len(filters.VulnStatuses))
			for i, status := range filters.VulnStatuses {
				placeholders[i] = "?"
				vulnFilterArgs = append(vulnFilterArgs, status)
			}
			conditions = append(conditions, "nv.fix_status IN ("+strings.Join(placeholders, ",")+")")
		}

		if len(filters.PackageTypes) > 0 {
			placeholders := make([]string, len(filters.PackageTypes))
			for i, pkgType := range filters.PackageTypes {
				placeholders[i] = "?"
				vulnFilterArgs = append(vulnFilterArgs, pkgType)
			}
			conditions = append(conditions, "np.type IN ("+strings.Join(placeholders, ",")+")")
		}

		if len(conditions) > 0 {
			vulnFilter = " AND " + strings.Join(conditions, " AND ")
		}
	}

	// Build node filter clause
	nodeFilter := ""
	var nodeFilterArgs []interface{}
	if len(filters.OSNames) > 0 {
		placeholders := make([]string, len(filters.OSNames))
		for i, os := range filters.OSNames {
			placeholders[i] = "?"
			nodeFilterArgs = append(nodeFilterArgs, os)
		}
		nodeFilter = " WHERE n.os_release IN (" + strings.Join(placeholders, ",") + ")"
	}

	// Build query with optional package join for vulnerability counts
	var query string
	var args []interface{}

	if len(filters.PackageTypes) > 0 {
		// Need to join with node_packages to filter by package type
		query = `
		SELECT
			n.name,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.status, 'unknown') as status,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = n.id) as package_count,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity = 'Critical'` + vulnFilter + `) as critical,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity = 'High'` + vulnFilter + `) as high,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity = 'Medium'` + vulnFilter + `) as medium,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity = 'Low'` + vulnFilter + `) as low,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity = 'Negligible'` + vulnFilter + `) as negligible,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id AND nv.severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')` + vulnFilter + `) as unknown,
			(SELECT COUNT(*) FROM node_vulnerabilities nv
				JOIN node_packages np ON nv.package_id = np.id
				WHERE nv.node_id = n.id` + vulnFilter + `) as total
		FROM nodes n` + nodeFilter + `
		ORDER BY n.name`

		// Add args for each subquery (7 severity counts + total = 8 subqueries)
		for i := 0; i < 8; i++ {
			args = append(args, vulnFilterArgs...)
		}
		args = append(args, nodeFilterArgs...)
	} else if len(filters.VulnStatuses) > 0 {
		// Only filtering by vuln status, no package join needed
		query = `
		SELECT
			n.name,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.status, 'unknown') as status,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = n.id) as package_count,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Critical'` + vulnFilter + `) as critical,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'High'` + vulnFilter + `) as high,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Medium'` + vulnFilter + `) as medium,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Low'` + vulnFilter + `) as low,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Negligible'` + vulnFilter + `) as negligible,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')` + vulnFilter + `) as unknown,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id` + vulnFilter + `) as total
		FROM nodes n` + nodeFilter + `
		ORDER BY n.name`

		// Add args for each subquery (7 severity counts + total = 8 subqueries)
		for i := 0; i < 8; i++ {
			args = append(args, vulnFilterArgs...)
		}
		args = append(args, nodeFilterArgs...)
	} else {
		// No vulnerability filtering, use simple query
		query = `
		SELECT
			n.name,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.status, 'unknown') as status,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = n.id) as package_count,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Critical') as critical,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'High') as high,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Medium') as medium,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Low') as low,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Negligible') as negligible,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')) as unknown,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id) as total
		FROM nodes n` + nodeFilter + `
		ORDER BY n.name`

		args = append(args, nodeFilterArgs...)
	}

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query node summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	summaries := make([]nodes.NodeSummary, 0)
	for rows.Next() {
		var summary nodes.NodeSummary
		err := rows.Scan(&summary.NodeName, &summary.OSRelease, &summary.Status, &summary.PackageCount, &summary.Critical, &summary.High,
			&summary.Medium, &summary.Low, &summary.Negligible, &summary.Unknown, &summary.Total)
		if err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
		}
		// Calculate status description based on status
		summary.StatusDescription = getNodeStatusDescription(summary.Status)
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// getNodeStatusDescription returns a human-readable description for a node scan status
func getNodeStatusDescription(status string) string {
	switch status {
	case "completed":
		return "Scan complete"
	case "scanning_vulnerabilities":
		return "Scanning vulnerabilities"
	case "generating_sbom":
		return "Generating SBOM"
	case "scanning":
		return "Scanning"
	case "pending":
		return "Pending"
	case "sbom_failed":
		return "SBOM generation failed"
	case "vuln_scan_failed":
		return "Vulnerability scan failed"
	case "error":
		return "Error"
	default:
		return "Unknown"
	}
}

// GetNodeDistributionSummary returns averaged vulnerability counts grouped by OS distribution
// Only includes nodes with completed scans (status = 'completed')
func (db *DB) GetNodeDistributionSummary() ([]nodes.NodeDistributionSummary, error) {
	rows, err := db.conn.Query(`
		SELECT
			COALESCE(n.os_release, 'Unknown') as os_name,
			COUNT(DISTINCT n.id) as node_count,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Critical')), 0) as avg_critical,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'High')), 0) as avg_high,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Medium')), 0) as avg_medium,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Low')), 0) as avg_low,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity = 'Negligible')), 0) as avg_negligible,
			COALESCE(AVG((SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.node_id = n.id AND nv.severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible'))), 0) as avg_unknown,
			COALESCE(AVG((SELECT COUNT(*) FROM node_packages np WHERE np.node_id = n.id)), 0) as avg_packages
		FROM nodes n
		WHERE n.status = 'completed'
		GROUP BY COALESCE(n.os_release, 'Unknown')
		ORDER BY node_count DESC, os_name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node distribution summary: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	summaries := make([]nodes.NodeDistributionSummary, 0)
	for rows.Next() {
		var summary nodes.NodeDistributionSummary
		err := rows.Scan(&summary.OSName, &summary.NodeCount, &summary.AvgCritical, &summary.AvgHigh,
			&summary.AvgMedium, &summary.AvgLow, &summary.AvgNegligible, &summary.AvgUnknown, &summary.AvgPackages)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution summary row: %w", err)
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// GetNodesNeedingRescan returns nodes that need to be rescanned due to grype DB update
func (db *DB) GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at
		FROM nodes
		WHERE status = ?
		AND (grype_db_built IS NULL OR grype_db_built < ?)
	`, StatusCompleted.String(), currentGrypeDBBuilt.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes needing rescan: %w", err)
	}

	// Collect all rows first before making additional queries
	// This avoids SQLite connection issues with nested queries
	var nodeRows []NodeRow
	for rows.Next() {
		var row NodeRow
		err := rows.Scan(
			&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
			&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
			&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
			&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
		)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		nodeRows = append(nodeRows, row)
	}
	_ = rows.Close()

	// Now convert rows to NodeWithStatus (which makes additional queries)
	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	result := make([]nodes.NodeWithStatus, 0, len(nodeRows))
	for _, row := range nodeRows {
		node, err := db.nodeRowToNodeWithStatus(&row)
		if err != nil {
			return nil, err
		}
		result = append(result, *node)
	}

	return result, nil
}

// NodeFilterOptions contains filter options for node-related pages
type NodeFilterOptions struct {
	OSNames      []string `json:"osNames"`
	VulnStatuses []string `json:"vulnStatuses"`
	PackageTypes []string `json:"packageTypes"`
}

// NodeVulnerabilityForMetrics contains vulnerability data for metrics export
// This struct combines node, package, and vulnerability data in a single row
type NodeVulnerabilityForMetrics struct {
	// Node info
	NodeName      string
	Hostname      string
	OSRelease     string
	KernelVersion string
	Architecture  string
	// Vulnerability info
	VulnID         int64
	CVEID          string
	Severity       string
	Score          float64
	FixStatus      string
	FixVersion     string
	KnownExploited int
	// Package info
	PackageName    string
	PackageVersion string
	PackageType    string
	Count          int
}

// GetNodeVulnerabilitiesForMetrics retrieves all node vulnerabilities with full context for metrics export
// Returns a denormalized view joining nodes, node_packages, and node_vulnerabilities
// Uses existing indexes: idx_nodes_status, idx_node_vulnerabilities_node, idx_node_vulnerabilities_package
func (db *DB) GetNodeVulnerabilitiesForMetrics() ([]NodeVulnerabilityForMetrics, error) {
	rows, err := db.conn.Query(`
		SELECT
			n.name,
			COALESCE(n.hostname, '') as hostname,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.kernel_version, '') as kernel_version,
			COALESCE(n.architecture, '') as architecture,
			nv.id as vuln_id,
			nv.cve_id,
			COALESCE(nv.severity, 'Unknown') as severity,
			COALESCE(nv.score, 0) as score,
			COALESCE(nv.fix_status, 'unknown') as fix_status,
			COALESCE(nv.fix_version, '') as fix_version,
			COALESCE(nv.known_exploited, 0) as known_exploited,
			np.name as package_name,
			np.version as package_version,
			COALESCE(np.type, '') as package_type,
			COALESCE(nv.count, 1) as count
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		JOIN node_packages np ON nv.package_id = np.id
		WHERE n.status = 'completed'
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node vulnerabilities for metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	result := make([]NodeVulnerabilityForMetrics, 0)
	for rows.Next() {
		var v NodeVulnerabilityForMetrics
		err := rows.Scan(
			&v.NodeName, &v.Hostname, &v.OSRelease, &v.KernelVersion, &v.Architecture,
			&v.VulnID, &v.CVEID, &v.Severity, &v.Score, &v.FixStatus, &v.FixVersion, &v.KnownExploited,
			&v.PackageName, &v.PackageVersion, &v.PackageType, &v.Count,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan node vulnerability row: %w", err)
		}
		result = append(result, v)
	}

	return result, nil
}

// GetScannedNodes retrieves all completed nodes for the bjorn2scan_node_scanned metric
func (db *DB) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at
		FROM nodes
		WHERE status = 'completed'
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query scanned nodes: %w", err)
	}

	// Collect all rows first before making additional queries
	var nodeRows []NodeRow
	for rows.Next() {
		var row NodeRow
		err := rows.Scan(
			&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
			&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
			&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
			&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
		)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		nodeRows = append(nodeRows, row)
	}
	_ = rows.Close()

	// Convert rows to NodeWithStatus (skips the additional queries for counts since we don't need them for metrics)
	result := make([]nodes.NodeWithStatus, 0, len(nodeRows))
	for _, row := range nodeRows {
		node := nodes.NodeWithStatus{
			Node: nodes.Node{
				Name: row.Name,
			},
			NodeScanStatus: nodes.NodeScanStatus{
				Status: "completed",
			},
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}
		if row.Hostname.Valid {
			node.Hostname = row.Hostname.String
		}
		if row.OSRelease.Valid {
			node.OSRelease = row.OSRelease.String
		}
		if row.KernelVersion.Valid {
			node.KernelVersion = row.KernelVersion.String
		}
		if row.Architecture.Valid {
			node.Architecture = row.Architecture.String
		}
		result = append(result, node)
	}

	return result, nil
}

// GetNodeFilterOptions returns distinct values for node filter dropdowns
func (db *DB) GetNodeFilterOptions() (*NodeFilterOptions, error) {
	options := &NodeFilterOptions{
		OSNames:      make([]string, 0),
		VulnStatuses: make([]string, 0),
		PackageTypes: make([]string, 0),
	}

	// Get distinct OS releases from nodes
	osRows, err := db.conn.Query(`
		SELECT DISTINCT os_release FROM nodes
		WHERE os_release IS NOT NULL AND os_release != ''
		ORDER BY os_release
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query OS releases: %w", err)
	}
	for osRows.Next() {
		var osName string
		if err := osRows.Scan(&osName); err == nil && osName != "" {
			options.OSNames = append(options.OSNames, osName)
		}
	}
	_ = osRows.Close()

	// Get distinct fix statuses from node vulnerabilities
	vulnRows, err := db.conn.Query(`
		SELECT DISTINCT fix_status FROM node_vulnerabilities
		WHERE fix_status IS NOT NULL AND fix_status != ''
		ORDER BY fix_status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vuln statuses: %w", err)
	}
	for vulnRows.Next() {
		var status string
		if err := vulnRows.Scan(&status); err == nil && status != "" {
			options.VulnStatuses = append(options.VulnStatuses, status)
		}
	}
	_ = vulnRows.Close()

	// Get distinct package types from node packages
	pkgRows, err := db.conn.Query(`
		SELECT DISTINCT type FROM node_packages
		WHERE type IS NOT NULL AND type != ''
		ORDER BY type
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query package types: %w", err)
	}
	for pkgRows.Next() {
		var pkgType string
		if err := pkgRows.Scan(&pkgType); err == nil && pkgType != "" {
			options.PackageTypes = append(options.PackageTypes, pkgType)
		}
	}
	_ = pkgRows.Close()

	return options, nil
}
