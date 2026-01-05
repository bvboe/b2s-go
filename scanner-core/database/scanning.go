package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// GetImageStatus returns the unified status for an image by digest
// Returns: Status constant (pending, generating_sbom, sbom_failed, sbom_unavailable,
//          scanning_vulnerabilities, vuln_scan_failed, completed)
func (db *DB) GetImageStatus(digest string) (Status, error) {
	var status string
	err := db.conn.QueryRow(`
		SELECT status FROM container_images
		WHERE digest = ?
	`, digest).Scan(&status)

	if err == sql.ErrNoRows {
		return StatusPending, nil // Image not found means pending
	}
	if err != nil {
		return "", fmt.Errorf("failed to get status: %w", err)
	}

	return Status(status), nil
}

// GetImageScanStatus is deprecated, use GetImageStatus instead
// Provided for backward compatibility during migration
func (db *DB) GetImageScanStatus(digest string) (string, error) {
	status, err := db.GetImageStatus(digest)
	if err != nil {
		return "", err
	}

	// Map new status to old scan_status
	switch status {
	case StatusCompleted, StatusScanningVulnerabilities, StatusVulnScanFailed:
		return "scanned", nil
	case StatusGeneratingSBOM:
		return "scanning", nil
	case StatusSBOMFailed, StatusSBOMUnavailable:
		return "failed", nil
	default:
		return "pending", nil
	}
}

// IsScanDataComplete checks if an image has complete scan data (SBOM and vulnerabilities)
// Returns true only if status is "completed" AND both SBOM and vulnerability data exist
func (db *DB) IsScanDataComplete(digest string) (bool, error) {
	var status string
	var hasSBOM bool
	var hasVulns bool

	err := db.conn.QueryRow(`
		SELECT
			status,
			sbom IS NOT NULL AND LENGTH(sbom) > 0,
			vulnerabilities IS NOT NULL AND LENGTH(vulnerabilities) > 0
		FROM container_images
		WHERE digest = ?
	`, digest).Scan(&status, &hasSBOM, &hasVulns)

	if err == sql.ErrNoRows {
		return false, nil // Image not found means incomplete
	}
	if err != nil {
		return false, fmt.Errorf("failed to check scan data completeness: %w", err)
	}

	// Data is complete only if status is completed AND we have both SBOM and vulnerabilities
	return status == string(StatusCompleted) && hasSBOM && hasVulns, nil
}

// UpdateStatus updates the unified status for an image
func (db *DB) UpdateStatus(digest string, status Status, errorMsg string) error {
	var sbomScannedAt, vulnsScannedAt interface{}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Set timestamps based on status
	switch status {
	case StatusScanningVulnerabilities, StatusSBOMFailed, StatusSBOMUnavailable:
		// SBOM stage just completed (success or failure)
		sbomScannedAt = timestamp
	case StatusCompleted, StatusVulnScanFailed:
		// Vulnerability scan just completed (success or failure)
		vulnsScannedAt = timestamp
	}

	_, err := db.conn.Exec(`
		UPDATE container_images
		SET status = ?,
		    status_error = ?,
		    sbom_scanned_at = COALESCE(sbom_scanned_at, ?),
		    vulns_scanned_at = COALESCE(vulns_scanned_at, ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, status.String(), errorMsg, sbomScannedAt, vulnsScannedAt, digest)

	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	return nil
}

// UpdateScanStatus is deprecated, use UpdateStatus instead
// Provided for backward compatibility during migration
func (db *DB) UpdateScanStatus(digest string, status string, errorMsg string) error {
	// Map old status to new unified status
	var newStatus Status
	switch status {
	case "scanning":
		newStatus = StatusGeneratingSBOM
	case "scanned":
		newStatus = StatusScanningVulnerabilities
	case "failed":
		newStatus = StatusSBOMFailed
	default:
		newStatus = StatusPending
	}

	return db.UpdateStatus(digest, newStatus, errorMsg)
}

// StoreSBOM stores the SBOM JSON for an image and marks it as scanned
func (db *DB) StoreSBOM(digest string, sbomJSON []byte) error {
	// Get image ID first
	var imageID int64
	err := db.conn.QueryRow(`SELECT id FROM container_images WHERE digest = ?`, digest).Scan(&imageID)
	if err != nil {
		return fmt.Errorf("failed to get image ID: %w", err)
	}

	_, err = db.conn.Exec(`
		UPDATE container_images
		SET sbom = ?,
		    status = ?,
		    status_error = NULL,
		    sbom_scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, string(sbomJSON), StatusScanningVulnerabilities.String(), time.Now().UTC().Format(time.RFC3339), digest)

	if err != nil {
		return fmt.Errorf("failed to store SBOM: %w", err)
	}

	// Parse and store SBOM data in packages table
	if err := parseSBOMData(db.conn, imageID, sbomJSON); err != nil {
		log.Printf("Warning: Failed to parse SBOM data for digest %s: %v", digest, err)
		// Don't fail the whole operation if parsing fails
	}

	return nil
}

// GetSBOM retrieves the SBOM JSON for an image by digest
func (db *DB) GetSBOM(digest string) ([]byte, error) {
	var sbom sql.NullString
	err := db.conn.QueryRow(`
		SELECT sbom FROM container_images
		WHERE digest = ?
	`, digest).Scan(&sbom)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	if !sbom.Valid || sbom.String == "" {
		return nil, fmt.Errorf("SBOM not available")
	}

	return []byte(sbom.String), nil
}

// GetImagesByScanStatus is deprecated, use GetImagesByStatus instead
// Returns all images with a specific scan status (maps old status to new unified status)
func (db *DB) GetImagesByScanStatus(status string) ([]ContainerImage, error) {
	// Map old status values to new unified status values
	var statusFilter string
	switch status {
	case "pending":
		// Include pending and generating_sbom
		statusFilter = "status IN ('pending', 'generating_sbom')"
	case "scanning":
		statusFilter = "status = 'generating_sbom'"
	case "scanned":
		// Include all statuses that indicate SBOM is complete
		statusFilter = "status IN ('scanning_vulnerabilities', 'vuln_scan_failed', 'completed')"
	case "failed":
		// Include all failure statuses
		statusFilter = "status IN ('sbom_failed', 'sbom_unavailable', 'vuln_scan_failed')"
	default:
		return nil, fmt.Errorf("unknown scan status: %s", status)
	}

	rows, err := db.conn.Query(`
		SELECT id, digest, created_at, updated_at
		FROM container_images
		WHERE `+statusFilter+`
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images by scan status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		err := rows.Scan(&img.ID, &img.Digest, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, nil
}

// GetImagesByStatus returns all images with a specific unified status
func (db *DB) GetImagesByStatus(status Status) ([]ContainerImage, error) {
	rows, err := db.conn.Query(`
		SELECT id, digest, created_at, updated_at
		FROM container_images
		WHERE status = ?
		ORDER BY created_at DESC
	`, status.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query images by status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		err := rows.Scan(&img.ID, &img.Digest, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, nil
}

// GetFirstInstanceForImage returns the first container instance for a given image digest
// This is used to determine which node to scan from
func (db *DB) GetFirstInstanceForImage(digest string) (*ContainerInstanceRow, error) {
	var inst ContainerInstanceRow
	err := db.conn.QueryRow(`
		SELECT
			ci.id, ci.namespace, ci.pod, ci.container,
			ci.repository, ci.tag, ci.image_id, img.digest,
			ci.created_at, ci.node_name, ci.container_runtime
		FROM container_instances ci
		JOIN container_images img ON ci.image_id = img.id
		WHERE img.digest = ?
		ORDER BY ci.created_at ASC
		LIMIT 1
	`, digest).Scan(&inst.ID, &inst.Namespace, &inst.Pod, &inst.Container,
		&inst.Repository, &inst.Tag, &inst.ImageID, &inst.Digest,
		&inst.CreatedAt, &inst.NodeName, &inst.ContainerRuntime)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no instances found for image")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get first instance: %w", err)
	}

	return &inst, nil
}

// GetImageVulnerabilityStatus is deprecated, use GetImageStatus instead
// Provided for backward compatibility during migration
func (db *DB) GetImageVulnerabilityStatus(digest string) (string, error) {
	status, err := db.GetImageStatus(digest)
	if err != nil {
		return "", err
	}

	// Map new status to old vulnerability_status
	switch status {
	case StatusCompleted:
		return "scanned", nil
	case StatusScanningVulnerabilities:
		return "scanning", nil
	case StatusVulnScanFailed:
		return "failed", nil
	default:
		return "pending", nil
	}
}

// UpdateVulnerabilityStatus is deprecated, use UpdateStatus instead
// Provided for backward compatibility during migration
func (db *DB) UpdateVulnerabilityStatus(digest string, status string, errorMsg string) error {
	// Map old vulnerability status to new unified status
	var newStatus Status
	switch status {
	case "scanning":
		newStatus = StatusScanningVulnerabilities
	case "scanned":
		newStatus = StatusCompleted
	case "failed":
		newStatus = StatusVulnScanFailed
	default:
		// If called with pending, check if SBOM is ready
		imgStatus, _ := db.GetImageStatus(digest)
		if imgStatus.HasSBOM() {
			newStatus = StatusScanningVulnerabilities
		} else {
			newStatus = StatusPending
		}
	}

	return db.UpdateStatus(digest, newStatus, errorMsg)
}

// StoreVulnerabilities stores the vulnerability scan JSON for an image and marks it as scanned
// grypeDBBuilt is the build timestamp of the grype vulnerability database used for scanning (can be zero for unknown)
func (db *DB) StoreVulnerabilities(digest string, vulnJSON []byte, grypeDBBuilt time.Time) error {
	// Get image ID first
	var imageID int64
	err := db.conn.QueryRow(`SELECT id FROM container_images WHERE digest = ?`, digest).Scan(&imageID)
	if err != nil {
		return fmt.Errorf("failed to get image ID: %w", err)
	}

	// Format grype DB built timestamp (empty string if zero)
	var grypeDBBuiltStr *string
	if !grypeDBBuilt.IsZero() {
		s := grypeDBBuilt.UTC().Format(time.RFC3339)
		grypeDBBuiltStr = &s
	}

	_, err = db.conn.Exec(`
		UPDATE container_images
		SET vulnerabilities = ?,
		    status = ?,
		    status_error = NULL,
		    vulns_scanned_at = ?,
		    grype_db_built = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, string(vulnJSON), StatusCompleted.String(), time.Now().UTC().Format(time.RFC3339), grypeDBBuiltStr, digest)

	if err != nil {
		return fmt.Errorf("failed to store vulnerabilities: %w", err)
	}

	// Parse and store vulnerability data in vulnerabilities table
	if err := parseVulnerabilityData(db.conn, imageID, vulnJSON); err != nil {
		log.Printf("Warning: Failed to parse vulnerability data for digest %s: %v", digest, err)
		// Don't fail the whole operation if parsing fails
	}

	return nil
}

// GetVulnerabilities retrieves the vulnerability scan JSON for an image by digest
func (db *DB) GetVulnerabilities(digest string) ([]byte, error) {
	var vuln sql.NullString
	err := db.conn.QueryRow(`
		SELECT vulnerabilities FROM container_images
		WHERE digest = ?
	`, digest).Scan(&vuln)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}

	if !vuln.Valid || vuln.String == "" {
		return nil, fmt.Errorf("vulnerabilities not available")
	}

	return []byte(vuln.String), nil
}
