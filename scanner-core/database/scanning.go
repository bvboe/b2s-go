package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// GetImageScanStatus returns the scan status for an image by digest
// Returns: "pending", "scanning", "scanned", or "failed"
func (db *DB) GetImageScanStatus(digest string) (string, error) {
	var status string
	err := db.conn.QueryRow(`
		SELECT scan_status FROM container_images
		WHERE digest = ?
	`, digest).Scan(&status)

	if err == sql.ErrNoRows {
		return "pending", nil // Image not found means not scanned
	}
	if err != nil {
		return "", fmt.Errorf("failed to get scan status: %w", err)
	}

	return status, nil
}

// IsScanDataComplete checks if an image has complete scan data (SBOM and vulnerabilities)
// Returns true only if status is "scanned" AND both SBOM and vulnerability data exist
func (db *DB) IsScanDataComplete(digest string) (bool, error) {
	var status string
	var hasSBOM bool
	var hasVulns bool

	err := db.conn.QueryRow(`
		SELECT
			scan_status,
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

	// Data is complete only if status is scanned AND we have both SBOM and vulnerabilities
	return status == "scanned" && hasSBOM && hasVulns, nil
}

// UpdateScanStatus updates the scan status and error message for an image
func (db *DB) UpdateScanStatus(digest string, status string, errorMsg string) error {
	var scannedAt interface{}
	if status == "scanned" {
		scannedAt = time.Now().UTC().Format(time.RFC3339)
	}

	_, err := db.conn.Exec(`
		UPDATE container_images
		SET scan_status = ?,
		    scan_error = ?,
		    scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, status, errorMsg, scannedAt, digest)

	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	return nil
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
		    scan_status = 'scanned',
		    scan_error = NULL,
		    scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, string(sbomJSON), time.Now().UTC().Format(time.RFC3339), digest)

	if err != nil {
		return fmt.Errorf("failed to store SBOM: %w", err)
	}

	// Parse and store SBOM data in packages and image_summary tables
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

// GetImagesByS canStatus returns all images with a specific scan status
func (db *DB) GetImagesByScanStatus(status string) ([]ContainerImage, error) {
	rows, err := db.conn.Query(`
		SELECT id, digest, created_at, updated_at,
		       scan_status, scan_error, scanned_at
		FROM container_images
		WHERE scan_status = ?
		ORDER BY created_at DESC
	`, status)
	if err != nil {
		return nil, fmt.Errorf("failed to query images by scan status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		var scanStatus, scanError sql.NullString
		var scannedAt sql.NullString

		err := rows.Scan(&img.ID, &img.Digest,
			&img.CreatedAt, &img.UpdatedAt,
			&scanStatus, &scanError, &scannedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}

		if scanStatus.Valid {
			img.ScanStatus = scanStatus.String
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

// GetImageVulnerabilityStatus returns the vulnerability scan status for an image by digest
// Returns: "pending", "scanning", "scanned", or "failed"
func (db *DB) GetImageVulnerabilityStatus(digest string) (string, error) {
	var status string
	err := db.conn.QueryRow(`
		SELECT vulnerability_status FROM container_images
		WHERE digest = ?
	`, digest).Scan(&status)

	if err == sql.ErrNoRows {
		return "pending", nil // Image not found means not scanned
	}
	if err != nil {
		return "", fmt.Errorf("failed to get vulnerability status: %w", err)
	}

	return status, nil
}

// UpdateVulnerabilityStatus updates the vulnerability scan status and error message for an image
func (db *DB) UpdateVulnerabilityStatus(digest string, status string, errorMsg string) error {
	var scannedAt interface{}
	if status == "scanned" {
		scannedAt = time.Now().UTC().Format(time.RFC3339)
	}

	_, err := db.conn.Exec(`
		UPDATE container_images
		SET vulnerability_status = ?,
		    vulnerability_error = ?,
		    vulnerabilities_scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, status, errorMsg, scannedAt, digest)

	if err != nil {
		return fmt.Errorf("failed to update vulnerability status: %w", err)
	}

	return nil
}

// StoreVulnerabilities stores the vulnerability scan JSON for an image and marks it as scanned
func (db *DB) StoreVulnerabilities(digest string, vulnJSON []byte) error {
	// Get image ID first
	var imageID int64
	err := db.conn.QueryRow(`SELECT id FROM container_images WHERE digest = ?`, digest).Scan(&imageID)
	if err != nil {
		return fmt.Errorf("failed to get image ID: %w", err)
	}

	_, err = db.conn.Exec(`
		UPDATE container_images
		SET vulnerabilities = ?,
		    vulnerability_status = 'scanned',
		    vulnerability_error = NULL,
		    vulnerabilities_scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, string(vulnJSON), time.Now().UTC().Format(time.RFC3339), digest)

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
