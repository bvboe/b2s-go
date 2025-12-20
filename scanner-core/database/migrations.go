package database

import (
	"database/sql"
	"fmt"
	"log"
)

const currentSchemaVersion = 11

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
	{
		version: 3,
		name:    "add_sbom_and_node_tracking",
		up:      migrateToV3,
	},
	{
		version: 4,
		name:    "add_vulnerability_scanning",
		up:      migrateToV4,
	},
	{
		version: 5,
		name:    "remove_redundant_sbom_fields",
		up:      migrateToV5,
	},
	{
		version: 6,
		name:    "add_sbom_vulnerability_tables",
		up:      migrateToV6,
	},
	{
		version: 7,
		name:    "add_vulnerability_risk_fields",
		up:      migrateToV7,
	},
	{
		version: 8,
		name:    "unified_status_field",
		up:      migrateToV8,
	},
	{
		version: 9,
		name:    "move_os_name_to_images",
		up:      migrateToV9,
	},
	{
		version: 10,
		name:    "drop_image_summary",
		up:      migrateToV10,
	},
	{
		version: 11,
		name:    "add_scan_status_table",
		up:      migrateToV11,
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

		-- Scan status lookup table
		CREATE TABLE IF NOT EXISTS scan_status (
			status TEXT PRIMARY KEY,
			description TEXT NOT NULL,
			sort_order INTEGER NOT NULL
		);

		-- Populate scan status lookup table
		INSERT INTO scan_status (status, description, sort_order) VALUES
			('completed', 'Scan complete', 1),
			('pending', 'Pending scan', 2),
			('scanning_vulnerabilities', 'Running vulnerability scan', 3),
			('generating_sbom', 'Retrieving SBOM', 4),
			('sbom_unavailable', 'Unable to scan', 5),
			('vuln_scan_failed', 'Scan failed', 6);
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

// migrateToV3 adds SBOM storage and node tracking capabilities
func migrateToV3(conn *sql.DB) error {
	// Start a transaction for the migration
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Step 1: Add SBOM and scan tracking columns to container_images
	_, err = tx.Exec(`
		ALTER TABLE container_images ADD COLUMN sbom TEXT;
		ALTER TABLE container_images ADD COLUMN scan_status TEXT DEFAULT 'pending';
		ALTER TABLE container_images ADD COLUMN scan_error TEXT;
		ALTER TABLE container_images ADD COLUMN scanned_at DATETIME;
	`)
	if err != nil {
		return fmt.Errorf("failed to add SBOM columns to container_images: %w", err)
	}

	// Step 2: Add node and runtime tracking columns to container_instances
	_, err = tx.Exec(`
		ALTER TABLE container_instances ADD COLUMN node_name TEXT;
		ALTER TABLE container_instances ADD COLUMN container_runtime TEXT;
	`)
	if err != nil {
		return fmt.Errorf("failed to add node tracking columns to container_instances: %w", err)
	}

	// Step 3: Create index on scan_status for efficient queries
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_images_scan_status ON container_images(scan_status);
	`)
	if err != nil {
		return fmt.Errorf("failed to create scan_status index: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// migrateToV4 adds vulnerability scanning capabilities
func migrateToV4(conn *sql.DB) error {
	// Start a transaction for the migration
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Step 1: Add vulnerability scanning columns to container_images
	_, err = tx.Exec(`
		ALTER TABLE container_images ADD COLUMN vulnerabilities TEXT;
		ALTER TABLE container_images ADD COLUMN vulnerability_status TEXT DEFAULT 'pending';
		ALTER TABLE container_images ADD COLUMN vulnerability_error TEXT;
		ALTER TABLE container_images ADD COLUMN vulnerabilities_scanned_at DATETIME;
	`)
	if err != nil {
		return fmt.Errorf("failed to add vulnerability columns to container_images: %w", err)
	}

	// Step 2: Create index on vulnerability_status for efficient queries
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_images_vulnerability_status ON container_images(vulnerability_status);
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerability_status index: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// migrateToV5 removes redundant sbom_requested and sbom_received fields
// These fields are replaced by scan_status and vulnerability_status tracking
func migrateToV5(conn *sql.DB) error {
	// Start a transaction for the migration
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
	// Step 1: Create new table without sbom_requested and sbom_received columns
	_, err = tx.Exec(`
		CREATE TABLE container_images_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			digest TEXT UNIQUE NOT NULL,
			sbom TEXT,
			scan_status TEXT DEFAULT 'pending',
			scan_error TEXT,
			scanned_at DATETIME,
			vulnerabilities TEXT,
			vulnerability_status TEXT DEFAULT 'pending',
			vulnerability_error TEXT,
			vulnerabilities_scanned_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new images table: %w", err)
	}

	// Step 2: Copy data from old table to new table
	_, err = tx.Exec(`
		INSERT INTO container_images_new (
			id, digest, sbom, scan_status, scan_error, scanned_at,
			vulnerabilities, vulnerability_status, vulnerability_error, vulnerabilities_scanned_at,
			created_at, updated_at
		)
		SELECT
			id, digest, sbom, scan_status, scan_error, scanned_at,
			vulnerabilities, vulnerability_status, vulnerability_error, vulnerabilities_scanned_at,
			created_at, updated_at
		FROM container_images
	`)
	if err != nil {
		return fmt.Errorf("failed to copy data to new table: %w", err)
	}

	// Step 3: Drop old table
	_, err = tx.Exec(`DROP TABLE container_images`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %w", err)
	}

	// Step 4: Rename new table
	_, err = tx.Exec(`ALTER TABLE container_images_new RENAME TO container_images`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %w", err)
	}

	// Step 5: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_images_scan_status ON container_images(scan_status);
		CREATE INDEX IF NOT EXISTS idx_images_vulnerability_status ON container_images(vulnerability_status);
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

// migrateToV6 adds tables for parsed SBOM and vulnerability data
func migrateToV6(conn *sql.DB) error {
	// Start a transaction for the migration
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Step 1: Create packages table
	_, err = tx.Exec(`
		CREATE TABLE packages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			image_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			version TEXT,
			type TEXT,
			number_of_instances INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (image_id) REFERENCES container_images(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create packages table: %w", err)
	}

	// Step 2: Create indexes for packages table
	_, err = tx.Exec(`
		CREATE INDEX idx_packages_image ON packages(image_id);
		CREATE INDEX idx_packages_type ON packages(type);
	`)
	if err != nil {
		return fmt.Errorf("failed to create packages indexes: %w", err)
	}

	// Step 3: Create vulnerabilities table
	_, err = tx.Exec(`
		CREATE TABLE vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			image_id INTEGER NOT NULL,
			cve_id TEXT NOT NULL,
			package_name TEXT,
			package_version TEXT,
			package_type TEXT,
			severity TEXT,
			fix_status TEXT,
			fixed_version TEXT,
			known_exploits INTEGER DEFAULT 0,
			count INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (image_id) REFERENCES container_images(id),
			UNIQUE(image_id, cve_id, package_name, package_version, package_type)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerabilities table: %w", err)
	}

	// Step 4: Create indexes for vulnerabilities table
	_, err = tx.Exec(`
		CREATE INDEX idx_vulnerabilities_image ON vulnerabilities(image_id);
		CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
		CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerabilities indexes: %w", err)
	}

	// Step 5: Create image_summary table
	_, err = tx.Exec(`
		CREATE TABLE image_summary (
			image_id INTEGER PRIMARY KEY,
			package_count INTEGER DEFAULT 0,
			os_name TEXT,
			os_version TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (image_id) REFERENCES container_images(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create image_summary table: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Step 6: Parse existing SBOM and vulnerability data
	log.Println("Migration v6: Processing existing SBOM and vulnerability data...")
	if err := migrateExistingData(conn); err != nil {
		log.Printf("Warning: Failed to migrate existing data: %v", err)
		// Don't fail the migration if data processing fails
	}

	return nil
}

// migrateExistingData processes existing SBOM and vulnerability JSON blobs
func migrateExistingData(conn *sql.DB) error {
	// Query all images that have SBOM or vulnerability data
	rows, err := conn.Query(`
		SELECT id, digest, sbom, vulnerabilities
		FROM container_images
		WHERE (sbom IS NOT NULL AND sbom != '')
		   OR (vulnerabilities IS NOT NULL AND vulnerabilities != '')
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}

	// Read all data first before closing the rows to avoid deadlock
	type imageData struct {
		imageID  int64
		digest   string
		sbomJSON string
		vulnJSON string
	}

	var imagesToProcess []imageData
	for rows.Next() {
		var imageID int64
		var digest string
		var sbomJSON, vulnJSON sql.NullString

		if err := rows.Scan(&imageID, &digest, &sbomJSON, &vulnJSON); err != nil {
			log.Printf("Warning: Failed to scan row: %v", err)
			continue
		}

		data := imageData{
			imageID: imageID,
			digest:  digest,
		}
		if sbomJSON.Valid {
			data.sbomJSON = sbomJSON.String
		}
		if vulnJSON.Valid {
			data.vulnJSON = vulnJSON.String
		}

		imagesToProcess = append(imagesToProcess, data)
	}
	if err := rows.Close(); err != nil {
		log.Printf("Warning: Failed to close rows: %v", err)
	}

	// Now process the data
	processed := 0
	for _, data := range imagesToProcess {
		// Process SBOM if available
		if data.sbomJSON != "" {
			if err := parseSBOMData(conn, data.imageID, []byte(data.sbomJSON)); err != nil {
				log.Printf("Warning: Failed to parse SBOM for image %d (%s): %v", data.imageID, data.digest, err)
			}
		}

		// Process vulnerabilities if available
		if data.vulnJSON != "" {
			if err := parseVulnerabilityData(conn, data.imageID, []byte(data.vulnJSON)); err != nil {
				log.Printf("Warning: Failed to parse vulnerabilities for image %d (%s): %v", data.imageID, data.digest, err)
			}
		}

		processed++
		if processed%10 == 0 {
			log.Printf("Migration v6: Processed %d images...", processed)
		}
	}

	log.Printf("Migration v6: Completed processing %d images", processed)
	return nil
}

// migrateToV7 adds risk, EPSS, and knownExploited fields to vulnerabilities table
func migrateToV7(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Add new columns to vulnerabilities table
	_, err = tx.Exec(`
		ALTER TABLE vulnerabilities ADD COLUMN risk REAL DEFAULT 0.0;
		ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL DEFAULT 0.0;
		ALTER TABLE vulnerabilities ADD COLUMN epss_percentile REAL DEFAULT 0.0;
		ALTER TABLE vulnerabilities ADD COLUMN known_exploited INTEGER DEFAULT 0;
	`)
	if err != nil {
		return fmt.Errorf("failed to add new columns: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration v7: Added risk, EPSS, and known_exploited columns to vulnerabilities table")
	return nil
}

// migrateToV8 adds unified status field replacing scan_status and vulnerability_status
func migrateToV8(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Println("Migration v8: Adding unified status field...")

	// Add new status columns
	_, err = tx.Exec(`
		ALTER TABLE container_images ADD COLUMN status TEXT DEFAULT 'pending';
		ALTER TABLE container_images ADD COLUMN status_error TEXT;
		ALTER TABLE container_images ADD COLUMN sbom_scanned_at DATETIME;
		ALTER TABLE container_images ADD COLUMN vulns_scanned_at DATETIME;
	`)
	if err != nil {
		return fmt.Errorf("failed to add new status columns: %w", err)
	}

	// Migrate data from old columns to unified status
	log.Println("Migration v8: Migrating status data...")
	_, err = tx.Exec(`
		UPDATE container_images
		SET
			status = CASE
				-- Both complete
				WHEN vulnerability_status = 'scanned' THEN 'completed'

				-- Vulnerability scanning stage
				WHEN vulnerability_status = 'scanning' THEN 'scanning_vulnerabilities'
				WHEN vulnerability_status = 'failed' THEN 'vuln_scan_failed'

				-- SBOM generation stage
				WHEN scan_status = 'scanned' THEN 'scanning_vulnerabilities'  -- SBOM done, vulns pending
				WHEN scan_status = 'scanning' THEN 'generating_sbom'
				WHEN scan_status = 'failed' THEN 'sbom_failed'

				-- Default
				ELSE 'pending'
			END,
			status_error = COALESCE(vulnerability_error, scan_error),
			sbom_scanned_at = scanned_at,
			vulns_scanned_at = vulnerabilities_scanned_at
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate status data: %w", err)
	}

	// Create index on new status field
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_images_status ON container_images(status);
	`)
	if err != nil {
		return fmt.Errorf("failed to create status index: %w", err)
	}

	// Drop old status columns by recreating the table without them
	log.Println("Migration v8: Removing old status columns...")
	_, err = tx.Exec(`
		-- Create new table without old status columns
		CREATE TABLE container_images_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			digest TEXT UNIQUE NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			status_error TEXT,
			sbom TEXT,
			vulnerabilities TEXT,
			sbom_scanned_at DATETIME,
			vulns_scanned_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Copy data from old table to new table
		INSERT INTO container_images_new (
			id, digest, status, status_error, sbom, vulnerabilities,
			sbom_scanned_at, vulns_scanned_at, created_at, updated_at
		)
		SELECT
			id, digest, status, status_error, sbom, vulnerabilities,
			sbom_scanned_at, vulns_scanned_at, created_at, updated_at
		FROM container_images;

		-- Drop old table
		DROP TABLE container_images;

		-- Rename new table
		ALTER TABLE container_images_new RENAME TO container_images;

		-- Recreate indexes
		CREATE INDEX idx_images_digest ON container_images(digest);
		CREATE INDEX idx_images_status ON container_images(status);
	`)
	if err != nil {
		return fmt.Errorf("failed to drop old status columns: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration v8: Successfully migrated to unified status field")
	return nil
}

// migrateToV9 moves os_name and os_version from image_summary to container_images
func migrateToV9(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Println("Migration v9: Moving os_name and os_version to container_images...")

	// Add os_name and os_version columns to container_images
	_, err = tx.Exec(`
		ALTER TABLE container_images ADD COLUMN os_name TEXT;
		ALTER TABLE container_images ADD COLUMN os_version TEXT;
	`)
	if err != nil {
		return fmt.Errorf("failed to add OS columns: %w", err)
	}

	// Migrate data from image_summary to container_images
	_, err = tx.Exec(`
		UPDATE container_images
		SET os_name = (
			SELECT os_name
			FROM image_summary
			WHERE image_summary.image_id = container_images.id
		),
		os_version = (
			SELECT os_version
			FROM image_summary
			WHERE image_summary.image_id = container_images.id
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate OS data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration v9: Successfully moved os_name and os_version to container_images")
	log.Println("Note: image_summary table is deprecated and will be removed in a future migration")
	return nil
}

// migrateToV10 drops the image_summary table (package_count is now calculated dynamically)
func migrateToV10(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Println("Migration v10: Dropping image_summary table...")

	// Drop the image_summary table
	_, err = tx.Exec(`DROP TABLE IF EXISTS image_summary`)
	if err != nil {
		return fmt.Errorf("failed to drop image_summary table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration v10: Successfully dropped image_summary table")
	log.Println("Note: package_count is now calculated dynamically from packages table")
	return nil
}

// migrateToV11 adds the scan_status lookup table for existing databases
func migrateToV11(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Println("Migration v11: Creating scan_status lookup table...")

	// Create scan_status table
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS scan_status (
			status TEXT PRIMARY KEY,
			description TEXT NOT NULL,
			sort_order INTEGER NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create scan_status table: %w", err)
	}

	// Populate scan status lookup table (INSERT OR IGNORE in case rows already exist)
	_, err = tx.Exec(`
		INSERT OR IGNORE INTO scan_status (status, description, sort_order) VALUES
			('completed', 'Scan complete', 1),
			('pending', 'Pending scan', 2),
			('scanning_vulnerabilities', 'Running vulnerability scan', 3),
			('generating_sbom', 'Retrieving SBOM', 4),
			('sbom_unavailable', 'Unable to scan', 5),
			('vuln_scan_failed', 'Scan failed', 6);
	`)
	if err != nil {
		return fmt.Errorf("failed to populate scan_status table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Migration v11: Successfully created scan_status table")
	return nil
}
