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
	var sbom struct {
		Artifacts []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		} `json:"artifacts"`
	}

	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Insert packages
	for _, pkg := range sbom.Artifacts {
		_, err = tx.Exec(`
			INSERT INTO node_packages (node_id, name, version, type, language, purl)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (node_id, name, version, type) DO UPDATE SET
				language = excluded.language,
				purl = excluded.purl
		`, nodeID, pkg.Name, pkg.Version, pkg.Type, pkg.Language, pkg.PURL)
		if err != nil {
			return fmt.Errorf("failed to insert package: %w", err)
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

	log.Printf("Stored SBOM for node %s: %d packages", name, len(sbom.Artifacts))
	return nil
}

// StoreNodeVulnerabilities stores vulnerabilities for a node
// Uses batched inserts to handle large vulnerability counts efficiently
func (db *DB) StoreNodeVulnerabilities(name string, vulnJSON []byte, grypeDBBuilt time.Time) error {
	const batchSize = 500 // Number of vulnerabilities to insert per transaction

	// Get node ID first (outside transaction)
	var nodeID int64
	err := db.conn.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID)
	if err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Parse vulnerability report
	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID       string  `json:"id"`
				Severity string  `json:"severity"`
				CVSS     []struct {
					Score float64 `json:"score"`
				} `json:"cvss"`
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
		} `json:"matches"`
	}

	if err := json.Unmarshal(vulnJSON, &report); err != nil {
		return fmt.Errorf("failed to parse vulnerability report: %w", err)
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

	// Delete existing vulnerabilities in a separate transaction
	if _, err := db.conn.Exec(`DELETE FROM node_vulnerabilities WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("failed to delete existing vulnerabilities: %w", err)
	}

	// Process vulnerabilities in batches
	totalInserted := 0
	for i := 0; i < len(report.Matches); i += batchSize {
		end := i + batchSize
		if end > len(report.Matches) {
			end = len(report.Matches)
		}
		batch := report.Matches[i:end]

		tx, err := db.conn.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for batch %d: %w", i/batchSize, err)
		}

		stmt, err := tx.Prepare(`
			INSERT INTO node_vulnerabilities (node_id, package_id, cve_id, severity, score, fix_status, fix_version)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to prepare statement: %w", err)
		}

		batchInserted := 0
		for _, match := range batch {
			// Look up package ID from map
			key := match.Artifact.Name + "|" + match.Artifact.Version + "|" + match.Artifact.Type
			packageID, found := packageMap[key]
			if !found {
				// Package not found, skip this vulnerability
				continue
			}

			var score float64
			if len(match.Vulnerability.CVSS) > 0 {
				score = match.Vulnerability.CVSS[0].Score
			}

			fixStatus := match.Vulnerability.Fix.State
			var fixVersion string
			if len(match.Vulnerability.Fix.Versions) > 0 {
				fixVersion = match.Vulnerability.Fix.Versions[0]
			}

			_, err = stmt.Exec(nodeID, packageID, match.Vulnerability.ID, match.Vulnerability.Severity, score, fixStatus, fixVersion)
			if err != nil {
				log.Printf("Warning: failed to insert vulnerability %s: %v", match.Vulnerability.ID, err)
				continue
			}
			batchInserted++
		}

		_ = stmt.Close()

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit batch %d: %w", i/batchSize, err)
		}

		totalInserted += batchInserted
		log.Printf("Stored vulnerability batch %d/%d (%d vulnerabilities)", i/batchSize+1, (len(report.Matches)+batchSize-1)/batchSize, batchInserted)
	}

	// Update node status in a final transaction
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

	log.Printf("Stored vulnerabilities for node %s: %d total (from %d matches)", name, totalInserted, len(report.Matches))
	return nil
}

// GetNodePackages retrieves all packages for a node with vulnerability counts
func (db *DB) GetNodePackages(name string) ([]nodes.NodePackage, error) {
	rows, err := db.conn.Query(`
		SELECT np.id, np.node_id, np.name, np.version, np.type, np.language, np.purl, np.details,
			(SELECT COUNT(*) FROM node_vulnerabilities nv WHERE nv.package_id = np.id) as vuln_count
		FROM node_packages np
		JOIN nodes n ON np.node_id = n.id
		WHERE n.name = ?
		ORDER BY np.name, np.version
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var packages []nodes.NodePackage
	for rows.Next() {
		var pkg nodes.NodePackage
		var language, purl, details sql.NullString
		err := rows.Scan(&pkg.ID, &pkg.NodeID, &pkg.Name, &pkg.Version, &pkg.Type, &language, &purl, &details, &pkg.VulnCount)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}
		if language.Valid {
			pkg.Language = language.String
		}
		if purl.Valid {
			pkg.PURL = purl.String
		}
		if details.Valid {
			pkg.Details = details.String
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetNodeVulnerabilities retrieves all vulnerabilities for a node
func (db *DB) GetNodeVulnerabilities(name string) ([]nodes.NodeVulnerability, error) {
	rows, err := db.conn.Query(`
		SELECT nv.id, nv.node_id, nv.package_id, nv.cve_id, nv.severity, nv.score,
			nv.fix_status, nv.fix_version, nv.known_exploited, nv.details, nv.created_at
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		WHERE n.name = ?
		ORDER BY nv.severity DESC, nv.cve_id
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var vulns []nodes.NodeVulnerability
	for rows.Next() {
		var vuln nodes.NodeVulnerability
		var score sql.NullFloat64
		var fixStatus, fixVersion, details sql.NullString
		err := rows.Scan(&vuln.ID, &vuln.NodeID, &vuln.PackageID, &vuln.CVEID, &vuln.Severity, &score,
			&fixStatus, &fixVersion, &vuln.KnownExploited, &details, &vuln.CreatedAt)
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
		if details.Valid {
			vuln.Details = details.String
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
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
		err := rows.Scan(&summary.NodeName, &summary.OSRelease, &summary.PackageCount, &summary.Critical, &summary.High,
			&summary.Medium, &summary.Low, &summary.Negligible, &summary.Unknown, &summary.Total)
		if err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
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
