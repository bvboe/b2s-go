package database

import (
	"database/sql"
	"fmt"
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
	_, err := db.conn.Exec(`
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
		SELECT id, digest, sbom_requested, sbom_received, created_at, updated_at,
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
		var sbomRequested, sbomReceived int
		var scanStatus, scanError sql.NullString
		var scannedAt sql.NullString

		err := rows.Scan(&img.ID, &img.Digest,
			&sbomRequested, &sbomReceived, &img.CreatedAt, &img.UpdatedAt,
			&scanStatus, &scanError, &scannedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}

		img.SBOMRequested = sbomRequested == 1
		img.SBOMReceived = sbomReceived == 1
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
