package database

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// ContainerInstanceRow represents a container instance in the database
type ContainerInstanceRow struct {
	ID               int64  `json:"id"`
	Namespace        string `json:"namespace"`
	Pod              string `json:"pod"`
	Container        string `json:"container"`
	ImageID          int64  `json:"image_id"`
	Repository       string `json:"repository"`
	Tag              string `json:"tag"`
	Digest           string `json:"digest"`
	CreatedAt        string `json:"created_at"`
	NodeName         string `json:"node_name"`
	ContainerRuntime string `json:"container_runtime"`
}

// AddInstance adds a container instance to the database
// Returns whether the instance was newly created
func (db *DB) AddInstance(instance containers.ContainerInstance) (bool, error) {
	// Validate required fields
	if instance.Image.Digest == "" {
		return false, fmt.Errorf("cannot add instance without digest: namespace=%s, pod=%s, container=%s",
			instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
	}
	if instance.Image.Repository == "" {
		return false, fmt.Errorf("cannot add instance without repository: namespace=%s, pod=%s, container=%s",
			instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
	}
	if instance.ID.Namespace == "" || instance.ID.Pod == "" || instance.ID.Container == "" {
		return false, fmt.Errorf("cannot add instance with empty identifier: namespace=%s, pod=%s, container=%s",
			instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
	}

	// Start a transaction to ensure atomic operation across both tables
	tx, err := db.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// First, get or create the image (using transaction-aware helper)
	imageID, _, err := db.getOrCreateImageTx(tx, instance.Image)
	if err != nil {
		return false, fmt.Errorf("failed to get/create image: %w", err)
	}

	// Check if instance already exists and get its current image_id
	var existingID int64
	var existingImageID int64
	err = tx.QueryRow(`
		SELECT id, image_id FROM container_instances
		WHERE namespace = ? AND pod = ? AND container = ?
	`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container).Scan(&existingID, &existingImageID)

	if err == nil {
		// Instance already exists, check if image has changed
		if existingImageID != imageID {
			// Image has changed (or digest was empty before), update it
			_, err = tx.Exec(`
				UPDATE container_instances
				SET image_id = ?, repository = ?, tag = ?, node_name = ?, container_runtime = ?
				WHERE id = ?
			`, imageID, instance.Image.Repository, instance.Image.Tag, instance.NodeName, instance.ContainerRuntime, existingID)

			if err != nil {
				return false, fmt.Errorf("failed to update instance: %w", err)
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("failed to commit transaction: %w", err)
			}

			log.Printf("Updated container instance in database: namespace=%s, pod=%s, container=%s (image_id=%d)",
				instance.ID.Namespace, instance.ID.Pod, instance.ID.Container, imageID)
			return true, nil
		}

		// Image hasn't changed, nothing to do
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("failed to commit transaction: %w", err)
		}
		return false, nil
	}

	if err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to query instance: %w", err)
	}

	// Instance doesn't exist, create it
	_, err = tx.Exec(`
		INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id, node_name, container_runtime)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
		instance.Image.Repository, instance.Image.Tag, imageID, instance.NodeName, instance.ContainerRuntime)

	if err != nil {
		return false, fmt.Errorf("failed to insert instance: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("New container instance added to database: namespace=%s, pod=%s, container=%s (image_id=%d)",
		instance.ID.Namespace, instance.ID.Pod, instance.ID.Container, imageID)

	return true, nil
}

// RemoveInstance removes a container instance from the database
func (db *DB) RemoveInstance(id containers.ContainerInstanceID) error {
	result, err := db.conn.Exec(`
		DELETE FROM container_instances
		WHERE namespace = ? AND pod = ? AND container = ?
	`, id.Namespace, id.Pod, id.Container)

	if err != nil {
		return fmt.Errorf("failed to delete instance: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		log.Printf("Container instance removed from database: namespace=%s, pod=%s, container=%s",
			id.Namespace, id.Pod, id.Container)
	}

	return nil
}

// SetInstances replaces all instances with the given set and returns reconciliation statistics
func (db *DB) SetInstances(instances []containers.ContainerInstance) (*containers.ReconciliationStats, error) {
	// Validate all instances before starting transaction
	for i, instance := range instances {
		if instance.Image.Digest == "" {
			return nil, fmt.Errorf("instance %d has empty digest: namespace=%s, pod=%s, container=%s",
				i, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
		}
		if instance.Image.Repository == "" {
			return nil, fmt.Errorf("instance %d has empty repository: namespace=%s, pod=%s, container=%s",
				i, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
		}
		if instance.ID.Namespace == "" || instance.ID.Pod == "" || instance.ID.Container == "" {
			return nil, fmt.Errorf("instance %d has empty identifier: namespace=%s, pod=%s, container=%s",
				i, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
		}
	}

	// Start a transaction to ensure atomic replacement
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Count existing instances before deletion
	var instancesRemoved int
	err = tx.QueryRow("SELECT COUNT(*) FROM container_instances").Scan(&instancesRemoved)
	if err != nil {
		return nil, fmt.Errorf("failed to count existing instances: %w", err)
	}

	// Delete all existing instances
	_, err = tx.Exec("DELETE FROM container_instances")
	if err != nil {
		return nil, fmt.Errorf("failed to delete instances: %w", err)
	}

	// Track statistics
	stats := &containers.ReconciliationStats{
		InstancesAdded:   len(instances),
		InstancesRemoved: instancesRemoved,
		ImagesAdded:      0,
	}

	// Add new instances
	for _, instance := range instances {
		// Get or create image (using transaction-aware helper)
		imageID, newImage, err := db.getOrCreateImageTx(tx, instance.Image)
		if err != nil {
			return nil, fmt.Errorf("failed to get/create image: %w", err)
		}

		if newImage {
			stats.ImagesAdded++
		}

		// Insert instance
		_, err = tx.Exec(`
			INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id, node_name, container_runtime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
			instance.Image.Repository, instance.Image.Tag, imageID, instance.NodeName, instance.ContainerRuntime)

		if err != nil {
			return nil, fmt.Errorf("failed to insert instance: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Reconciliation complete: added=%d, removed=%d, new_images=%d",
		stats.InstancesAdded, stats.InstancesRemoved, stats.ImagesAdded)
	return stats, nil
}

// GetAllInstances returns all container instances with their image information
func (db *DB) GetAllInstances() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT
			ci.id, ci.namespace, ci.pod, ci.container,
			ci.repository, ci.tag, ci.image_id, img.digest,
			ci.created_at, ci.node_name, ci.container_runtime
		FROM container_instances ci
		JOIN container_images img ON ci.image_id = img.id
		ORDER BY ci.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query instances: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var instances []ContainerInstanceRow
	for rows.Next() {
		var inst ContainerInstanceRow
		var nodeName, containerRuntime sql.NullString
		err := rows.Scan(&inst.ID, &inst.Namespace, &inst.Pod, &inst.Container,
			&inst.Repository, &inst.Tag, &inst.ImageID, &inst.Digest, &inst.CreatedAt,
			&nodeName, &containerRuntime)
		if err != nil {
			return nil, fmt.Errorf("failed to scan instance: %w", err)
		}
		if nodeName.Valid {
			inst.NodeName = nodeName.String
		}
		if containerRuntime.Valid {
			inst.ContainerRuntime = containerRuntime.String
		}
		instances = append(instances, inst)
	}

	return instances, nil
}

// CleanupStats holds statistics about a cleanup operation
type CleanupStats struct {
	ImagesRemoved        int // Number of container images deleted
	PackagesRemoved      int // Number of package entries deleted
	VulnerabilitiesRemoved int // Number of vulnerability entries deleted
}

// CleanupOrphanedImages removes container_images that have no associated container_instances
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
		FROM container_images img
		WHERE NOT EXISTS (
			SELECT 1
			FROM container_instances ci
			WHERE ci.image_id = img.id
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
			FROM container_images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM container_instances ci
				WHERE ci.image_id = img.id
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
			FROM container_images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM container_instances ci
				WHERE ci.image_id = img.id
			)
		)
	`).Scan(&vulnerabilitiesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count orphaned vulnerabilities: %w", err)
	}

	// Delete vulnerabilities for orphaned images
	_, err = tx.Exec(`
		DELETE FROM vulnerabilities
		WHERE image_id IN (
			SELECT img.id
			FROM container_images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM container_instances ci
				WHERE ci.image_id = img.id
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete vulnerabilities: %w", err)
	}

	// Delete packages for orphaned images
	_, err = tx.Exec(`
		DELETE FROM packages
		WHERE image_id IN (
			SELECT img.id
			FROM container_images img
			WHERE NOT EXISTS (
				SELECT 1
				FROM container_instances ci
				WHERE ci.image_id = img.id
			)
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to delete packages: %w", err)
	}

	// Delete orphaned images
	_, err = tx.Exec(`
		DELETE FROM container_images
		WHERE NOT EXISTS (
			SELECT 1
			FROM container_instances ci
			WHERE ci.image_id = container_images.id
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
		ImagesRemoved:          orphanedCount,
		PackagesRemoved:        packagesCount,
		VulnerabilitiesRemoved: vulnerabilitiesCount,
	}

	log.Printf("Cleanup complete: removed %d images, %d packages, %d vulnerabilities",
		stats.ImagesRemoved, stats.PackagesRemoved, stats.VulnerabilitiesRemoved)

	return stats, nil
}
