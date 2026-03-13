package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
	var result []nodes.NodeWithStatus
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

// GetNodePackages retrieves all packages for a node
func (db *DB) GetNodePackages(name string) ([]nodes.NodePackage, error) {
	rows, err := db.conn.Query(`
		SELECT np.id, np.node_id, np.name, np.version, np.type, np.language, np.purl, np.details
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
		err := rows.Scan(&pkg.ID, &pkg.NodeID, &pkg.Name, &pkg.Version, &pkg.Type, &language, &purl, &details)
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

// GetNodeSummaries returns vulnerability summaries for all nodes
func (db *DB) GetNodeSummaries() ([]nodes.NodeSummary, error) {
	rows, err := db.conn.Query(`
		SELECT
			n.name,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = n.id) as package_count,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Critical') as critical,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'High') as high,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Medium') as medium,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Low') as low,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity = 'Negligible') as negligible,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id AND severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible')) as unknown,
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = n.id) as total
		FROM nodes n
		ORDER BY n.name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var summaries []nodes.NodeSummary
	for rows.Next() {
		var summary nodes.NodeSummary
		err := rows.Scan(&summary.NodeName, &summary.PackageCount, &summary.Critical, &summary.High,
			&summary.Medium, &summary.Low, &summary.Negligible, &summary.Unknown, &summary.Total)
		if err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
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
	var result []nodes.NodeWithStatus
	for _, row := range nodeRows {
		node, err := db.nodeRowToNodeWithStatus(&row)
		if err != nil {
			return nil, err
		}
		result = append(result, *node)
	}

	return result, nil
}
