package database

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// ContainerImage represents a container image in the database
type ContainerImage struct {
	ID            int64
	Digest        string
	SBOMRequested bool
	SBOMReceived  bool
	CreatedAt     string
	UpdatedAt     string
}

// GetOrCreateImage gets an existing image or creates a new one based on digest
// Returns the image ID and whether it was newly created
func (db *DB) GetOrCreateImage(image containers.ImageID) (int64, bool, error) {
	// Try to get existing image by digest
	var id int64
	err := db.conn.QueryRow(`
		SELECT id FROM container_images
		WHERE digest = ?
	`, image.Digest).Scan(&id)

	if err == nil {
		// Image already exists
		return id, false, nil
	}

	if err != sql.ErrNoRows {
		return 0, false, fmt.Errorf("failed to query image: %w", err)
	}

	// Image doesn't exist, create it
	result, err := db.conn.Exec(`
		INSERT INTO container_images (digest, sbom_requested)
		VALUES (?, 0)
	`, image.Digest)

	if err != nil {
		return 0, false, fmt.Errorf("failed to insert image: %w", err)
	}

	id, err = result.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("failed to get image ID: %w", err)
	}

	log.Printf("New image added to database: %s:%s (digest=%s, id=%d)",
		image.Repository, image.Tag, image.Digest, id)
	log.Printf("TODO: Request SBOM for image: %s:%s", image.Repository, image.Tag)

	return id, true, nil
}

// GetAllImages returns all container images from the database
func (db *DB) GetAllImages() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT id, digest, sbom_requested, sbom_received, created_at, updated_at
		FROM container_images
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		var sbomRequested, sbomReceived int
		err := rows.Scan(&img.ID, &img.Digest,
			&sbomRequested, &sbomReceived, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image: %w", err)
		}
		img.SBOMRequested = sbomRequested == 1
		img.SBOMReceived = sbomReceived == 1
		images = append(images, img)
	}

	return images, nil
}

// GetImageByID returns a container image by ID
func (db *DB) GetImageByID(id int64) (*ContainerImage, error) {
	var img ContainerImage
	var sbomRequested, sbomReceived int
	err := db.conn.QueryRow(`
		SELECT id, digest, sbom_requested, sbom_received, created_at, updated_at
		FROM container_images
		WHERE id = ?
	`, id).Scan(&img.ID, &img.Digest,
		&sbomRequested, &sbomReceived, &img.CreatedAt, &img.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}

	img.SBOMRequested = sbomRequested == 1
	img.SBOMReceived = sbomReceived == 1
	return &img, nil
}
