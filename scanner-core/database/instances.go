package database

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// ContainerRow represents a container in the database
type ContainerRow struct {
	ID               int64  `json:"id"`
	Namespace        string `json:"namespace"`
	Pod              string `json:"pod"`
	Name             string `json:"name"`
	ImageID          int64  `json:"image_id"`
	Reference        string `json:"reference"`
	Digest           string `json:"digest"`
	CreatedAt        string `json:"created_at"`
	NodeName         string `json:"node_name"`
	ContainerRuntime string `json:"container_runtime"`
}

// AddContainer adds a container to the database
// Returns whether the container was newly created
func (db *DB) AddContainer(c containers.Container) (bool, error) {
	// Validate required fields
	if c.Image.Digest == "" {
		return false, fmt.Errorf("cannot add container without digest: namespace=%s, pod=%s, name=%s",
			c.ID.Namespace, c.ID.Pod, c.ID.Name)
	}
	if c.Image.Reference == "" {
		return false, fmt.Errorf("cannot add container without reference: namespace=%s, pod=%s, name=%s",
			c.ID.Namespace, c.ID.Pod, c.ID.Name)
	}
	if c.ID.Namespace == "" || c.ID.Pod == "" || c.ID.Name == "" {
		return false, fmt.Errorf("cannot add container with empty identifier: namespace=%s, pod=%s, name=%s",
			c.ID.Namespace, c.ID.Pod, c.ID.Name)
	}

	// Start a transaction to ensure atomic operation across both tables
	tx, err := db.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First, get or create the image (using transaction-aware helper)
	imageID, _, err := db.getOrCreateImageTx(tx, c.Image)
	if err != nil {
		return false, fmt.Errorf("failed to get/create image: %w", err)
	}

	// Check if container already exists and get its current image_id
	var existingID int64
	var existingImageID int64
	err = tx.QueryRow(`
		SELECT id, image_id FROM containers
		WHERE namespace = ? AND pod = ? AND name = ?
	`, c.ID.Namespace, c.ID.Pod, c.ID.Name).Scan(&existingID, &existingImageID)

	if err == nil {
		// Container already exists, check if image has changed
		if existingImageID != imageID {
			// Image has changed (or digest was empty before), update it
			_, err = tx.Exec(`
				UPDATE containers
				SET image_id = ?, reference = ?, node_name = ?, container_runtime = ?
				WHERE id = ?
			`, imageID, c.Image.Reference, c.NodeName, c.ContainerRuntime, existingID)

			if err != nil {
				return false, fmt.Errorf("failed to update container: %w", err)
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("failed to commit transaction: %w", err)
			}

			log.Printf("Updated container in database: namespace=%s, pod=%s, name=%s (image_id=%d)",
				c.ID.Namespace, c.ID.Pod, c.ID.Name, imageID)
			return true, nil
		}

		// Image hasn't changed, nothing to do
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return false, nil
	}

	if err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to query container: %w", err)
	}

	// Container doesn't exist, create it
	_, err = tx.Exec(`
		INSERT INTO containers (namespace, pod, name, reference, image_id, node_name, container_runtime)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, c.ID.Namespace, c.ID.Pod, c.ID.Name,
		c.Image.Reference, imageID, c.NodeName, c.ContainerRuntime)

	if err != nil {
		return false, fmt.Errorf("failed to insert container: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("New container added to database: namespace=%s, pod=%s, name=%s (image_id=%d)",
		c.ID.Namespace, c.ID.Pod, c.ID.Name, imageID)

	return true, nil
}

// RemoveContainer removes a container from the database
func (db *DB) RemoveContainer(id containers.ContainerID) error {
	result, err := db.conn.Exec(`
		DELETE FROM containers
		WHERE namespace = ? AND pod = ? AND name = ?
	`, id.Namespace, id.Pod, id.Name)

	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		log.Printf("Container removed from database: namespace=%s, pod=%s, name=%s",
			id.Namespace, id.Pod, id.Name)
	}

	return nil
}

// SetContainers replaces all containers with the given set and returns reconciliation statistics
func (db *DB) SetContainers(containerList []containers.Container) (*containers.ReconciliationStats, error) {
	// Validate all containers before starting transaction
	for i, c := range containerList {
		if c.Image.Digest == "" {
			return nil, fmt.Errorf("container %d has empty digest: namespace=%s, pod=%s, name=%s",
				i, c.ID.Namespace, c.ID.Pod, c.ID.Name)
		}
		if c.Image.Reference == "" {
			return nil, fmt.Errorf("container %d has empty reference: namespace=%s, pod=%s, name=%s",
				i, c.ID.Namespace, c.ID.Pod, c.ID.Name)
		}
		if c.ID.Namespace == "" || c.ID.Pod == "" || c.ID.Name == "" {
			return nil, fmt.Errorf("container %d has empty identifier: namespace=%s, pod=%s, name=%s",
				i, c.ID.Namespace, c.ID.Pod, c.ID.Name)
		}
	}

	// Start a transaction to ensure atomic replacement
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Count existing containers before deletion
	var containersRemoved int
	err = tx.QueryRow("SELECT COUNT(*) FROM containers").Scan(&containersRemoved)
	if err != nil {
		return nil, fmt.Errorf("failed to count existing containers: %w", err)
	}

	// Delete all existing containers
	_, err = tx.Exec("DELETE FROM containers")
	if err != nil {
		return nil, fmt.Errorf("failed to delete containers: %w", err)
	}

	// Track statistics
	stats := &containers.ReconciliationStats{
		ContainersAdded:   len(containerList),
		ContainersRemoved: containersRemoved,
		ImagesAdded:       0,
	}

	// Add new containers
	for _, c := range containerList {
		// Get or create image (using transaction-aware helper)
		imageID, newImage, err := db.getOrCreateImageTx(tx, c.Image)
		if err != nil {
			return nil, fmt.Errorf("failed to get/create image: %w", err)
		}

		if newImage {
			stats.ImagesAdded++
		}

		// Insert container
		_, err = tx.Exec(`
			INSERT INTO containers (namespace, pod, name, reference, image_id, node_name, container_runtime)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, c.ID.Namespace, c.ID.Pod, c.ID.Name,
			c.Image.Reference, imageID, c.NodeName, c.ContainerRuntime)

		if err != nil {
			return nil, fmt.Errorf("failed to insert container: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Reconciliation complete: added=%d, removed=%d, new_images=%d",
		stats.ContainersAdded, stats.ContainersRemoved, stats.ImagesAdded)
	return stats, nil
}

// GetAllContainers returns all containers with their image information
func (db *DB) GetAllContainers() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT
			c.id, c.namespace, c.pod, c.name,
			c.reference, c.image_id, img.digest,
			c.created_at, c.node_name, c.container_runtime
		FROM containers c
		JOIN images img ON c.image_id = img.id
		ORDER BY c.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query containers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []ContainerRow
	for rows.Next() {
		var row ContainerRow
		var nodeName, containerRuntime sql.NullString
		err := rows.Scan(&row.ID, &row.Namespace, &row.Pod, &row.Name,
			&row.Reference, &row.ImageID, &row.Digest, &row.CreatedAt,
			&nodeName, &containerRuntime)
		if err != nil {
			return nil, fmt.Errorf("failed to scan container: %w", err)
		}
		if nodeName.Valid {
			row.NodeName = nodeName.String
		}
		if containerRuntime.Valid {
			row.ContainerRuntime = containerRuntime.String
		}
		result = append(result, row)
	}

	return result, nil
}

// CleanupStats holds statistics about a cleanup operation
type CleanupStats struct {
	ImagesRemoved              int // Number of container images deleted
	PackagesRemoved            int // Number of package entries deleted
	VulnerabilitiesRemoved     int // Number of vulnerability entries deleted
	PackageDetailsRemoved      int // Number of package_details entries deleted
	VulnerabilityDetailsRemoved int // Number of vulnerability_details entries deleted
}

// CleanupOrphanedImages removes images that have no associated containers
// This also cascades to delete related packages and vulnerabilities
func (db *DB) CleanupOrphanedImages() (*CleanupStats, error) {
	// Start a transaction
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Count orphaned images before deletion
	var orphanedCount int
	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM images img
		WHERE NOT EXISTS (
			SELECT 1
			FROM containers c
			WHERE c.image_id = img.id
		)
	`).Scan(&orphanedCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned images: %w", err)
	}

	if orphanedCount == 0 {
		// No cleanup needed
		log.Printf("Cleanup: no orphaned images found")
		return &CleanupStats{}, nil
	}

	// Count related data before deletion
	var packagesCount, vulnerabilitiesCount int

	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM packages p
		WHERE p.image_id IN (
			SELECT img.id
			FROM images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM containers c
				WHERE c.image_id = img.id
			)
		)
	`).Scan(&packagesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned packages: %w", err)
	}

	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM vulnerabilities v
		WHERE v.image_id IN (
			SELECT img.id
			FROM images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM containers c
				WHERE c.image_id = img.id
			)
		)
	`).Scan(&vulnerabilitiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned vulnerabilities: %w", err)
	}

	// Delete vulnerability_details for orphaned images (must be done before vulnerabilities)
	var vulnerabilityDetailsCount int
	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM vulnerability_details vd
		WHERE vd.vulnerability_id IN (
			SELECT v.id
			FROM vulnerabilities v
			WHERE v.image_id IN (
				SELECT img.id
				FROM images img
				WHERE NOT EXISTS (
					SELECT 1
					FROM containers c
					WHERE c.image_id = img.id
				)
			)
		)
	`).Scan(&vulnerabilityDetailsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned vulnerability_details: %w", err)
	}

	_, err = tx.Exec(`
		DELETE FROM vulnerability_details
		WHERE vulnerability_id IN (
			SELECT v.id
			FROM vulnerabilities v
			WHERE v.image_id IN (
				SELECT img.id
				FROM images img
				WHERE NOT EXISTS (
					SELECT 1
					FROM containers c
					WHERE c.image_id = img.id
				)
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete vulnerability_details: %w", err)
	}

	// Delete vulnerabilities for orphaned images
	_, err = tx.Exec(`
		DELETE FROM vulnerabilities
		WHERE image_id IN (
			SELECT img.id
			FROM images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM containers c
				WHERE c.image_id = img.id
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete vulnerabilities: %w", err)
	}

	// Delete package_details for orphaned images (must be done before packages)
	var packageDetailsCount int
	err = tx.QueryRow(`
		SELECT COUNT(*)
		FROM package_details pd
		WHERE pd.package_id IN (
			SELECT p.id
			FROM packages p
			WHERE p.image_id IN (
				SELECT img.id
				FROM images img
				WHERE NOT EXISTS (
					SELECT 1
					FROM containers c
					WHERE c.image_id = img.id
				)
			)
		)
	`).Scan(&packageDetailsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned package_details: %w", err)
	}

	_, err = tx.Exec(`
		DELETE FROM package_details
		WHERE package_id IN (
			SELECT p.id
			FROM packages p
			WHERE p.image_id IN (
				SELECT img.id
				FROM images img
				WHERE NOT EXISTS (
					SELECT 1
					FROM containers c
					WHERE c.image_id = img.id
				)
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete package_details: %w", err)
	}

	// Delete packages for orphaned images
	_, err = tx.Exec(`
		DELETE FROM packages
		WHERE image_id IN (
			SELECT img.id
			FROM images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM containers c
				WHERE c.image_id = img.id
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete packages: %w", err)
	}

	// Delete orphaned images
	_, err = tx.Exec(`
		DELETE FROM images
		WHERE NOT EXISTS (
			SELECT 1
			FROM containers c
			WHERE c.image_id = images.id
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete orphaned images: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	stats := &CleanupStats{
		ImagesRemoved:               orphanedCount,
		PackagesRemoved:             packagesCount,
		VulnerabilitiesRemoved:      vulnerabilitiesCount,
		PackageDetailsRemoved:       packageDetailsCount,
		VulnerabilityDetailsRemoved: vulnerabilityDetailsCount,
	}

	log.Printf("Cleanup complete: removed %d images, %d packages (%d details), %d vulnerabilities (%d details)",
		stats.ImagesRemoved, stats.PackagesRemoved, stats.PackageDetailsRemoved,
		stats.VulnerabilitiesRemoved, stats.VulnerabilityDetailsRemoved)

	return stats, nil
}
