package database

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// ContainerInstanceRow represents a container instance in the database
type ContainerInstanceRow struct {
	ID         int64  `json:"id"`
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	ImageID    int64  `json:"image_id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	CreatedAt  string `json:"created_at"`
}

// AddInstance adds a container instance to the database
// Returns whether the instance was newly created
func (db *DB) AddInstance(instance containers.ContainerInstance) (bool, error) {
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

	// Check if instance already exists
	var existingID int64
	err = tx.QueryRow(`
		SELECT id FROM container_instances
		WHERE namespace = ? AND pod = ? AND container = ?
	`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container).Scan(&existingID)

	if err == nil {
		// Instance already exists, do nothing
		// Commit the transaction (even though we didn't change anything)
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
		INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id)
		VALUES (?, ?, ?, ?, ?, ?)
	`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
		instance.Image.Repository, instance.Image.Tag, imageID)

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

// SetInstances replaces all instances with the given set
func (db *DB) SetInstances(instances []containers.ContainerInstance) error {
	// Start a transaction to ensure atomic replacement
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete all existing instances
	_, err = tx.Exec("DELETE FROM container_instances")
	if err != nil {
		return fmt.Errorf("failed to delete instances: %w", err)
	}

	// Add new instances
	for _, instance := range instances {
		// Get or create image (using transaction-aware helper)
		imageID, newImage, err := db.getOrCreateImageTx(tx, instance.Image)
		if err != nil {
			return fmt.Errorf("failed to get/create image: %w", err)
		}

		// Insert instance
		_, err = tx.Exec(`
			INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id)
			VALUES (?, ?, ?, ?, ?, ?)
		`, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
			instance.Image.Repository, instance.Image.Tag, imageID)

		if err != nil {
			return fmt.Errorf("failed to insert instance: %w", err)
		}

		if newImage {
			log.Printf("TODO: Request SBOM for image: %s:%s", instance.Image.Repository, instance.Image.Tag)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Set container instances in database: %d instances", len(instances))
	return nil
}

// GetAllInstances returns all container instances with their image information
func (db *DB) GetAllInstances() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT
			ci.id, ci.namespace, ci.pod, ci.container,
			ci.repository, ci.tag, ci.image_id, img.digest,
			ci.created_at
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
		err := rows.Scan(&inst.ID, &inst.Namespace, &inst.Pod, &inst.Container,
			&inst.Repository, &inst.Tag, &inst.ImageID, &inst.Digest, &inst.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan instance: %w", err)
		}
		instances = append(instances, inst)
	}

	return instances, nil
}
