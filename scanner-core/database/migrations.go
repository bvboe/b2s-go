package database

import (
	"database/sql"
	"fmt"
	"log"
)

const currentSchemaVersion = 2

type migration struct {
	version int
	name    string
	up      func(*sql.DB) error
}

var migrations = []migration{
	{
		version: 1,
		name:    "initial_schema",
		up:      migrateToV1,
	},
	{
		version: 2,
		name:    "remove_repo_tag_from_images",
		up:      migrateToV2,
	},
}

// ensureSchemaVersion checks the current schema version and applies necessary migrations
func (db *DB) ensureSchemaVersion() error {
	// Create schema_migrations table if it doesn't exist
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Get current version
	currentVersion, err := db.getCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	log.Printf("Current database schema version: %d, target version: %d", currentVersion, currentSchemaVersion)

	// Apply migrations in order
	for _, m := range migrations {
		if m.version <= currentVersion {
			continue // Already applied
		}

		log.Printf("Applying migration %d: %s", m.version, m.name)
		if err := m.up(db.conn); err != nil {
			return fmt.Errorf("failed to apply migration %d (%s): %w", m.version, m.name, err)
		}

		// Record migration
		_, err = db.conn.Exec(`
			INSERT INTO schema_migrations (version, name) VALUES (?, ?)
		`, m.version, m.name)
		if err != nil {
			return fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}

		log.Printf("Successfully applied migration %d: %s", m.version, m.name)
	}

	return nil
}

// getCurrentVersion returns the current schema version from the database
func (db *DB) getCurrentVersion() (int, error) {
	var version int
	err := db.conn.QueryRow(`
		SELECT COALESCE(MAX(version), 0) FROM schema_migrations
	`).Scan(&version)

	if err != nil {
		return 0, fmt.Errorf("failed to query schema version: %w", err)
	}

	return version, nil
}

// migrateToV1 creates the initial schema
func migrateToV1(conn *sql.DB) error {
	_, err := conn.Exec(`
		-- Container images table (original schema with repo/tag)
		CREATE TABLE IF NOT EXISTS container_images (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repository TEXT NOT NULL,
			tag TEXT NOT NULL,
			digest TEXT NOT NULL,
			sbom_requested INTEGER DEFAULT 0,
			sbom_received INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(repository, tag, digest)
		);

		CREATE INDEX IF NOT EXISTS idx_images_repo_tag ON container_images(repository, tag);
		CREATE INDEX IF NOT EXISTS idx_images_digest ON container_images(digest);

		-- Container instances table (original schema without repo/tag)
		CREATE TABLE IF NOT EXISTS container_instances (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			container TEXT NOT NULL,
			image_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(namespace, pod, container),
			FOREIGN KEY(image_id) REFERENCES container_images(id)
		);

		CREATE INDEX IF NOT EXISTS idx_instances_namespace ON container_instances(namespace);
		CREATE INDEX IF NOT EXISTS idx_instances_image ON container_instances(image_id);
	`)
	return err
}

// migrateToV2 removes repository and tag from images, adds them to instances
func migrateToV2(conn *sql.DB) error {
	// Start a transaction for the migration
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Step 1: Create new container_images table with only digest
	_, err = tx.Exec(`
		CREATE TABLE container_images_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			digest TEXT NOT NULL UNIQUE,
			sbom_requested INTEGER DEFAULT 0,
			sbom_received INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new images table: %w", err)
	}

	// Step 2: Migrate unique images (by digest) to new table
	_, err = tx.Exec(`
		INSERT INTO container_images_new (id, digest, sbom_requested, sbom_received, created_at, updated_at)
		SELECT
			MIN(id),
			digest,
			MAX(sbom_requested),
			MAX(sbom_received),
			MIN(created_at),
			MAX(updated_at)
		FROM container_images
		WHERE digest != ''
		GROUP BY digest
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate images data: %w", err)
	}

	// Step 3: Create new container_instances table with repository and tag
	_, err = tx.Exec(`
		CREATE TABLE container_instances_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			container TEXT NOT NULL,
			repository TEXT NOT NULL,
			tag TEXT NOT NULL,
			image_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(namespace, pod, container),
			FOREIGN KEY(image_id) REFERENCES container_images_new(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new instances table: %w", err)
	}

	// Step 4: Migrate instances data, joining with old images to get repo/tag
	_, err = tx.Exec(`
		INSERT INTO container_instances_new (id, namespace, pod, container, repository, tag, image_id, created_at)
		SELECT
			ci.id,
			ci.namespace,
			ci.pod,
			ci.container,
			COALESCE(img_old.repository, 'unknown'),
			COALESCE(img_old.tag, 'unknown'),
			img_new.id,
			ci.created_at
		FROM container_instances ci
		LEFT JOIN container_images img_old ON ci.image_id = img_old.id
		LEFT JOIN container_images_new img_new ON img_old.digest = img_new.digest AND img_old.digest != ''
		WHERE img_new.id IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate instances data: %w", err)
	}

	// Step 5: Drop old tables
	_, err = tx.Exec(`DROP TABLE container_instances`)
	if err != nil {
		return fmt.Errorf("failed to drop old instances table: %w", err)
	}

	_, err = tx.Exec(`DROP TABLE container_images`)
	if err != nil {
		return fmt.Errorf("failed to drop old images table: %w", err)
	}

	// Step 6: Rename new tables
	_, err = tx.Exec(`ALTER TABLE container_images_new RENAME TO container_images`)
	if err != nil {
		return fmt.Errorf("failed to rename images table: %w", err)
	}

	_, err = tx.Exec(`ALTER TABLE container_instances_new RENAME TO container_instances`)
	if err != nil {
		return fmt.Errorf("failed to rename instances table: %w", err)
	}

	// Step 7: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_instances_namespace ON container_instances(namespace);
		CREATE INDEX IF NOT EXISTS idx_instances_image ON container_instances(image_id);
	`)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
