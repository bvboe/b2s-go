package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

const currentSchemaVersion = 36

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
	{
		version: 12,
		name:    "add_unique_constraints_to_packages",
		up:      migrateToV12,
	},
	{
		version: 13,
		name:    "add_vulnerability_and_package_details_tables",
		up:      migrateToV13,
	},
	{
		version: 14,
		name:    "backfill_vulnerability_and_package_details",
		up:      migrateToV14,
	},
	{
		version: 15,
		name:    "update_details_to_store_all_instances",
		up:      migrateToV15,
	},
	{
		version: 16,
		name:    "update_package_details_with_complete_sbom_data",
		up:      migrateToV16,
	},
	{
		version: 17,
		name:    "update_package_details_with_struct_format",
		up:      migrateToV17,
	},
	{
		version: 18,
		name:    "update_vulnerability_details_with_raw_json",
		up:      migrateToV18,
	},
	{
		version: 19,
		name:    "remove_known_exploits_column",
		up:      migrateToV19,
	},
	{
		version: 20,
		name:    "add_performance_indexes",
		up:      migrateToV20,
	},
	{
		version: 21,
		name:    "add_grype_db_built_column",
		up:      migrateToV21,
	},
	{
		version: 22,
		name:    "add_job_executions_table",
		up:      migrateToV22,
	},
	{
		version: 23,
		name:    "add_metric_staleness_table", // renamed to app_state in v26
		up:      migrateToV23,
	},
	{
		version: 24,
		name:    "add_architecture_column",
		up:      migrateToV24,
	},
	{
		version: 25,
		name:    "populate_architecture_from_existing_sboms",
		up:      migrateToV25,
	},
	{
		version: 26,
		name:    "rename_metric_staleness_to_app_state",
		up:      migrateToV26,
	},
	{
		version: 27,
		name:    "add_reference_column_to_instances",
		up:      migrateToV27,
	},
	{
		version: 28,
		name:    "drop_repository_tag_columns",
		up:      migrateToV28,
	},
	{
		version: 29,
		name:    "rename_tables_to_match_docker_k8s_terminology",
		up:      migrateToV29,
	},
	{
		version: 30,
		name:    "add_nodes_tables",
		up:      migrateToV30,
	},
	{
		version: 31,
		name:    "add_node_performance_indexes",
		up:      migrateToV31,
	},
	{
		version: 32,
		name:    "add_node_package_instance_count",
		up:      migrateToV32,
	},
	{
		version: 33,
		name:    "add_node_vulnerability_deduplication",
		up:      migrateToV33,
	},
	{
		version: 34,
		name:    "add_node_detail_tables",
		up:      migrateToV34,
	},
	{
		version: 35,
		name:    "add_node_sbom_column",
		up:      migrateToV35,
	},
	{
		version: 36,
		name:    "add_metric_staleness_dedicated_table",
		up:      migrateToV36,
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

	log.Info("database schema version check",
		"current_version", currentVersion, "target_version", currentSchemaVersion)

	// Apply migrations in order
	for _, m := range migrations {
		if m.version <= currentVersion {
			continue // Already applied
		}

		log.Info("applying migration", "version", m.version, "name", m.name)
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

		log.Info("successfully applied migration", "version", m.version, "name", m.name)
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
	log.Info("migration v6: processing existing SBOM and vulnerability data")
	if err := migrateExistingData(conn); err != nil {
		log.Warn("migration v6: failed to migrate existing data", "error", err)
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
			log.Warn("migration v6: failed to scan row", "error", err)
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
		log.Warn("failed to close rows", "error", err)
	}

	// Now process the data
	processed := 0
	for _, data := range imagesToProcess {
		// Process SBOM if available
		if data.sbomJSON != "" {
			if err := parseSBOMData(conn, data.imageID, []byte(data.sbomJSON)); err != nil {
				log.Warn("migration v6: failed to parse SBOM",
					"image_id", data.imageID, "digest", data.digest, "error", err)
			}
		}

		// Process vulnerabilities if available
		if data.vulnJSON != "" {
			if err := parseVulnerabilityData(conn, data.imageID, []byte(data.vulnJSON)); err != nil {
				log.Warn("migration v6: failed to parse vulnerabilities",
					"image_id", data.imageID, "digest", data.digest, "error", err)
			}
		}

		processed++
		if processed%10 == 0 {
			log.Info("migration v6: processing progress", "processed", processed)
		}
	}

	log.Info("migration v6: completed processing", "images_processed", processed)
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

	log.Info("migration v7: added risk, EPSS, and known_exploited columns to vulnerabilities table")
	return nil
}

// migrateToV8 adds unified status field replacing scan_status and vulnerability_status
func migrateToV8(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v8: adding unified status field")

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
	log.Info("migration v8: migrating status data")
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
	log.Info("migration v8: removing old status columns")
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

	log.Info("migration v8: successfully migrated to unified status field")
	return nil
}

// migrateToV9 moves os_name and os_version from image_summary to container_images
func migrateToV9(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v9: moving os_name and os_version to container_images")

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

	log.Info("migration v9: successfully moved os_name and os_version to container_images")
	log.Info("note: image_summary table is deprecated and will be removed in a future migration")
	return nil
}

// migrateToV10 drops the image_summary table (package_count is now calculated dynamically)
func migrateToV10(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v10: dropping image_summary table")

	// Drop the image_summary table
	_, err = tx.Exec(`DROP TABLE IF EXISTS image_summary`)
	if err != nil {
		return fmt.Errorf("failed to drop image_summary table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v10: successfully dropped image_summary table")
	log.Info("note: package_count is now calculated dynamically from packages table")
	return nil
}

// migrateToV11 adds the scan_status lookup table for existing databases
func migrateToV11(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v11: creating scan_status lookup table")

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

	log.Info("migration v11: successfully created scan_status table")
	return nil
}

// migrateToV12 adds UNIQUE constraint to packages table on (image_id, name, version, type)
// and consolidates duplicate entries by summing number_of_instances
func migrateToV12(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v12: adding UNIQUE constraint to packages table")

	// Create new packages table with UNIQUE constraint
	_, err = tx.Exec(`
		CREATE TABLE packages_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			image_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			version TEXT,
			type TEXT,
			number_of_instances INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (image_id) REFERENCES container_images(id),
			UNIQUE(image_id, name, version, type)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new packages table: %w", err)
	}

	// Copy data from old table, aggregating duplicates
	log.Info("migration v12: consolidating duplicate packages")
	_, err = tx.Exec(`
		INSERT INTO packages_new (image_id, name, version, type, number_of_instances, created_at)
		SELECT
			image_id,
			name,
			version,
			type,
			SUM(number_of_instances) as number_of_instances,
			MIN(created_at) as created_at
		FROM packages
		GROUP BY image_id, name, version, type
	`)
	if err != nil {
		return fmt.Errorf("failed to copy packages data: %w", err)
	}

	// Drop old table
	_, err = tx.Exec(`DROP TABLE packages`)
	if err != nil {
		return fmt.Errorf("failed to drop old packages table: %w", err)
	}

	// Rename new table
	_, err = tx.Exec(`ALTER TABLE packages_new RENAME TO packages`)
	if err != nil {
		return fmt.Errorf("failed to rename packages table: %w", err)
	}

	// Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX idx_packages_image ON packages(image_id);
		CREATE INDEX idx_packages_type ON packages(type);
	`)
	if err != nil {
		return fmt.Errorf("failed to create packages indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v12: successfully added UNIQUE constraint to packages table")
	log.Info("note: duplicate packages have been consolidated by summing number_of_instances")
	return nil
}

// migrateToV13 adds vulnerability_details and package_details tables to store JSON details
func migrateToV13(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v13: creating vulnerability_details and package_details tables")

	// Create vulnerability_details table
	_, err = tx.Exec(`
		CREATE TABLE vulnerability_details (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vulnerability_id INTEGER NOT NULL,
			details TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			UNIQUE(vulnerability_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerability_details table: %w", err)
	}

	// Create index on vulnerability_id for fast lookups
	_, err = tx.Exec(`
		CREATE INDEX idx_vulnerability_details_vuln ON vulnerability_details(vulnerability_id)
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerability_details index: %w", err)
	}

	// Create package_details table
	_, err = tx.Exec(`
		CREATE TABLE package_details (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			package_id INTEGER NOT NULL,
			details TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE,
			UNIQUE(package_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create package_details table: %w", err)
	}

	// Create index on package_id for fast lookups
	_, err = tx.Exec(`
		CREATE INDEX idx_package_details_pkg ON package_details(package_id)
	`)
	if err != nil {
		return fmt.Errorf("failed to create package_details index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v13: successfully created vulnerability_details and package_details tables")
	return nil
}

// migrateToV14 backfills vulnerability_details and package_details tables with existing data
func migrateToV14(conn *sql.DB) error {
	log.Info("migration v14: backfilling vulnerability_details and package_details tables")

	// Get all image IDs that have SBOM or vulnerability data
	rows, err := conn.Query(`
		SELECT id
		FROM container_images
		WHERE (sbom IS NOT NULL AND sbom != '')
		   OR (vulnerabilities IS NOT NULL AND vulnerabilities != '')
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	var imageIDs []int64
	for rows.Next() {
		var imageID int64
		if err := rows.Scan(&imageID); err != nil {
			log.Warn("failed to scan image ID", "error", err)
			continue
		}
		imageIDs = append(imageIDs, imageID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating image rows: %w", err)
	}

	log.Info("migration v14: found images to backfill", "count", len(imageIDs))

	// Re-parse each image to populate details tables
	successCount := 0
	failCount := 0
	for _, imageID := range imageIDs {
		// Parse SBOM if available
		var sbomJSON sql.NullString
		err := conn.QueryRow(`SELECT sbom FROM container_images WHERE id = ?`, imageID).Scan(&sbomJSON)
		if err != nil {
			log.Warn("failed to get SBOM", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if sbomJSON.Valid && sbomJSON.String != "" {
			if err := parseSBOMData(conn, imageID, []byte(sbomJSON.String)); err != nil {
				log.Warn("failed to parse SBOM", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		// Parse vulnerabilities if available
		var vulnJSON sql.NullString
		err = conn.QueryRow(`SELECT vulnerabilities FROM container_images WHERE id = ?`, imageID).Scan(&vulnJSON)
		if err != nil {
			log.Warn("failed to get vulnerabilities", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if vulnJSON.Valid && vulnJSON.String != "" {
			if err := parseVulnerabilityData(conn, imageID, []byte(vulnJSON.String)); err != nil {
				log.Warn("failed to parse vulnerabilities", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		successCount++
		if successCount%10 == 0 {
			log.Info("migration v14: processing progress",
				"processed", successCount, "total", len(imageIDs))
		}
	}

	log.Info("migration v14: successfully backfilled details",
		"success_count", successCount, "fail_count", failCount)
	return nil
}

// migrateToV15 updates existing detail records to store arrays instead of single objects
func migrateToV15(conn *sql.DB) error {
	log.Info("migration v15: updating detail records to store all instances")

	// Clear existing details - they will be regenerated with all instances
	_, err := conn.Exec(`DELETE FROM vulnerability_details`)
	if err != nil {
		return fmt.Errorf("failed to clear vulnerability_details: %w", err)
	}

	_, err = conn.Exec(`DELETE FROM package_details`)
	if err != nil {
		return fmt.Errorf("failed to clear package_details: %w", err)
	}

	log.Info("migration v15: cleared existing details, will regenerate from raw SBOM/vulnerability data")

	// Get all image IDs that have SBOM or vulnerability data
	rows, err := conn.Query(`
		SELECT id
		FROM container_images
		WHERE (sbom IS NOT NULL AND sbom != '')
		   OR (vulnerabilities IS NOT NULL AND vulnerabilities != '')
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	var imageIDs []int64
	for rows.Next() {
		var imageID int64
		if err := rows.Scan(&imageID); err != nil {
			log.Warn("failed to scan image ID", "error", err)
			continue
		}
		imageIDs = append(imageIDs, imageID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating image rows: %w", err)
	}

	log.Info("migration v15: found images to regenerate details for", "count", len(imageIDs))

	// Re-parse each image to populate details tables with arrays
	successCount := 0
	failCount := 0
	for _, imageID := range imageIDs {
		// Parse SBOM if available
		var sbomJSON sql.NullString
		err := conn.QueryRow(`SELECT sbom FROM container_images WHERE id = ?`, imageID).Scan(&sbomJSON)
		if err != nil {
			log.Warn("failed to get SBOM", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if sbomJSON.Valid && sbomJSON.String != "" {
			if err := parseSBOMData(conn, imageID, []byte(sbomJSON.String)); err != nil {
				log.Warn("failed to parse SBOM", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		// Parse vulnerabilities if available
		var vulnJSON sql.NullString
		err = conn.QueryRow(`SELECT vulnerabilities FROM container_images WHERE id = ?`, imageID).Scan(&vulnJSON)
		if err != nil {
			log.Warn("failed to get vulnerabilities", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if vulnJSON.Valid && vulnJSON.String != "" {
			if err := parseVulnerabilityData(conn, imageID, []byte(vulnJSON.String)); err != nil {
				log.Warn("failed to parse vulnerabilities", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		successCount++
		if successCount%10 == 0 {
			log.Info("migration v15: processing progress",
				"processed", successCount, "total", len(imageIDs))
		}
	}

	log.Info("migration v15: successfully regenerated details",
		"success_count", successCount, "fail_count", failCount)
	return nil
}

// migrateToV16 regenerates package_details to include complete SBOM artifact data
// instead of just name/version/type
func migrateToV16(conn *sql.DB) error {
	log.Info("migration v16: updating package_details with complete SBOM artifact data")

	// Clear existing package details - they will be regenerated with complete data
	_, err := conn.Exec(`DELETE FROM package_details`)
	if err != nil {
		return fmt.Errorf("failed to clear package_details: %w", err)
	}

	// Get all image IDs that have SBOM data
	rows, err := conn.Query(`
		SELECT id
		FROM container_images
		WHERE sbom IS NOT NULL AND sbom != ''
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}

	var imageIDs []int64
	for rows.Next() {
		var imageID int64
		if err := rows.Scan(&imageID); err != nil {
			log.Warn("failed to scan image ID", "error", err)
			continue
		}
		imageIDs = append(imageIDs, imageID)
	}
	if err := rows.Close(); err != nil {
		log.Warn("failed to close rows", "error", err)
	}

	log.Info("migration v16: found images with SBOM data to process", "count", len(imageIDs))

	// Re-parse each image's SBOM to populate package_details with complete artifact data
	successCount := 0
	failCount := 0
	for _, imageID := range imageIDs {
		// Get SBOM data
		var sbomJSON sql.NullString
		err := conn.QueryRow(`SELECT sbom FROM container_images WHERE id = ?`, imageID).Scan(&sbomJSON)
		if err != nil {
			log.Warn("failed to query SBOM", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if sbomJSON.Valid && sbomJSON.String != "" {
			if err := parseSBOMData(conn, imageID, []byte(sbomJSON.String)); err != nil {
				log.Warn("failed to parse SBOM", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		successCount++
		if successCount%10 == 0 {
			log.Info("migration v16: processing progress",
				"processed", successCount, "total", len(imageIDs))
		}
	}

	log.Info("migration v16: successfully regenerated package details",
		"success_count", successCount, "fail_count", failCount)
	return nil
}

// migrateToV17 regenerates package_details using struct format for consistent field ordering
// This ensures packages display like CVEs with fields in a logical order, not alphabetically
func migrateToV17(conn *sql.DB) error {
	log.Info("migration v17: updating package_details with struct format for consistent field ordering")

	// Clear existing package details - they will be regenerated with struct format
	_, err := conn.Exec(`DELETE FROM package_details`)
	if err != nil {
		return fmt.Errorf("failed to clear package_details: %w", err)
	}

	// Get all image IDs that have SBOM data
	rows, err := conn.Query(`
		SELECT id
		FROM container_images
		WHERE sbom IS NOT NULL AND sbom != ''
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}

	var imageIDs []int64
	for rows.Next() {
		var imageID int64
		if err := rows.Scan(&imageID); err != nil {
			log.Warn("failed to scan image ID", "error", err)
			continue
		}
		imageIDs = append(imageIDs, imageID)
	}
	if err := rows.Close(); err != nil {
		log.Warn("failed to close rows", "error", err)
	}

	log.Info("migration v17: found images with SBOM data to process", "count", len(imageIDs))

	// Re-parse each image's SBOM to populate package_details with struct format
	successCount := 0
	failCount := 0
	for _, imageID := range imageIDs {
		// Get SBOM data
		var sbomJSON sql.NullString
		err := conn.QueryRow(`SELECT sbom FROM container_images WHERE id = ?`, imageID).Scan(&sbomJSON)
		if err != nil {
			log.Warn("failed to query SBOM", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if sbomJSON.Valid && sbomJSON.String != "" {
			if err := parseSBOMData(conn, imageID, []byte(sbomJSON.String)); err != nil {
				log.Warn("failed to parse SBOM", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		successCount++
		if successCount%10 == 0 {
			log.Info("migration v17: processing progress",
				"processed", successCount, "total", len(imageIDs))
		}
	}

	log.Info("migration v17: successfully regenerated package details",
		"success_count", successCount, "fail_count", failCount)
	return nil
}

// migrateToV18 regenerates vulnerability_details using raw JSON format
// This ensures vulnerabilities preserve ALL fields (current and future) from Grype output
func migrateToV18(conn *sql.DB) error {
	log.Info("migration v18: updating vulnerability_details with raw JSON format for complete data preservation")

	// Clear existing vulnerability details - they will be regenerated with raw JSON
	_, err := conn.Exec(`DELETE FROM vulnerability_details`)
	if err != nil {
		return fmt.Errorf("failed to clear vulnerability_details: %w", err)
	}

	// Get all image IDs that have vulnerability data
	rows, err := conn.Query(`
		SELECT id
		FROM container_images
		WHERE vulnerabilities IS NOT NULL AND vulnerabilities != ''
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}

	var imageIDs []int64
	for rows.Next() {
		var imageID int64
		if err := rows.Scan(&imageID); err != nil {
			log.Warn("failed to scan image ID", "error", err)
			continue
		}
		imageIDs = append(imageIDs, imageID)
	}
	if err := rows.Close(); err != nil {
		log.Warn("failed to close rows", "error", err)
	}

	log.Info("migration v18: found images with vulnerability data to process", "count", len(imageIDs))

	// Re-parse each image's vulnerabilities to populate vulnerability_details with raw JSON
	successCount := 0
	failCount := 0
	for _, imageID := range imageIDs {
		// Get vulnerability data
		var vulnJSON sql.NullString
		err := conn.QueryRow(`SELECT vulnerabilities FROM container_images WHERE id = ?`, imageID).Scan(&vulnJSON)
		if err != nil {
			log.Warn("failed to query vulnerabilities", "image_id", imageID, "error", err)
			failCount++
			continue
		}

		if vulnJSON.Valid && vulnJSON.String != "" {
			if err := parseVulnerabilityData(conn, imageID, []byte(vulnJSON.String)); err != nil {
				log.Warn("failed to parse vulnerabilities", "image_id", imageID, "error", err)
				failCount++
				continue
			}
		}

		successCount++
		if successCount%10 == 0 {
			log.Info("migration v18: processing progress",
				"processed", successCount, "total", len(imageIDs))
		}
	}

	log.Info("migration v18: successfully regenerated vulnerability details",
		"success_count", successCount, "fail_count", failCount)
	return nil
}

// migrateToV19 removes the deprecated known_exploits column from vulnerabilities table
// The known_exploited column (added in v7) provides the correct CISA KEV catalog count
func migrateToV19(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v19: removing deprecated known_exploits column from vulnerabilities table")

	// SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
	// Step 1: Create new table without known_exploits column
	_, err = tx.Exec(`
		CREATE TABLE vulnerabilities_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			image_id INTEGER NOT NULL,
			cve_id TEXT NOT NULL,
			package_name TEXT,
			package_version TEXT,
			package_type TEXT,
			severity TEXT,
			fix_status TEXT,
			fixed_version TEXT,
			count INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			risk REAL DEFAULT 0.0,
			epss_score REAL DEFAULT 0.0,
			epss_percentile REAL DEFAULT 0.0,
			known_exploited INTEGER DEFAULT 0,
			FOREIGN KEY (image_id) REFERENCES container_images(id),
			UNIQUE(image_id, cve_id, package_name, package_version, package_type)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new vulnerabilities table: %w", err)
	}

	// Step 2: Copy data from old table to new table (excluding known_exploits)
	_, err = tx.Exec(`
		INSERT INTO vulnerabilities_new (
			id, image_id, cve_id, package_name, package_version, package_type,
			severity, fix_status, fixed_version, count, created_at,
			risk, epss_score, epss_percentile, known_exploited
		)
		SELECT
			id, image_id, cve_id, package_name, package_version, package_type,
			severity, fix_status, fixed_version, count, created_at,
			risk, epss_score, epss_percentile, known_exploited
		FROM vulnerabilities
	`)
	if err != nil {
		return fmt.Errorf("failed to copy vulnerabilities data: %w", err)
	}

	// Step 3: Drop old table
	_, err = tx.Exec(`DROP TABLE vulnerabilities`)
	if err != nil {
		return fmt.Errorf("failed to drop old vulnerabilities table: %w", err)
	}

	// Step 4: Rename new table
	_, err = tx.Exec(`ALTER TABLE vulnerabilities_new RENAME TO vulnerabilities`)
	if err != nil {
		return fmt.Errorf("failed to rename vulnerabilities table: %w", err)
	}

	// Step 5: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX idx_vulnerabilities_image ON vulnerabilities(image_id);
		CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
		CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerabilities indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v19: successfully removed known_exploits column from vulnerabilities table")
	log.Info("note: use known_exploited column instead for CISA KEV catalog count")
	return nil
}

// migrateToV20 adds performance indexes for frequently accessed sort and filter operations
func migrateToV20(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v20: adding performance indexes")

	// Add index on container_images.created_at for ORDER BY optimization
	// Used by: GetAllImages, GetAllImageDetails, GetImagesByStatus, GetImagesByScanStatus
	log.Info("migration v20: creating index on container_images(created_at)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_images_created_at ON container_images(created_at)
	`)
	if err != nil {
		return fmt.Errorf("failed to create container_images created_at index: %w", err)
	}

	// Add index on container_instances.created_at for ORDER BY optimization
	// Used by: GetAllInstances, GetFirstInstanceForImage
	log.Info("migration v20: creating index on container_instances(created_at)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_instances_created_at ON container_instances(created_at)
	`)
	if err != nil {
		return fmt.Errorf("failed to create container_instances created_at index: %w", err)
	}

	// Add composite index on vulnerabilities(image_id, severity) for GROUP BY optimization
	// Used by: GetImageDetails vulnerability counts aggregation
	log.Info("migration v20: creating composite index on vulnerabilities(image_id, severity)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_vulnerabilities_image_severity ON vulnerabilities(image_id, severity)
	`)
	if err != nil {
		return fmt.Errorf("failed to create vulnerabilities image_severity composite index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v20: successfully added performance indexes")
	log.Info("migration v20: container_images(created_at): optimizes ORDER BY in image list queries")
	log.Info("migration v20: container_instances(created_at): optimizes ORDER BY in instance list queries")
	log.Info("migration v20: vulnerabilities(image_id, severity): optimizes GROUP BY in vulnerability count queries")
	return nil
}

// migrateToV21 adds grype_db_built column to track which vulnerability database version was used for scanning
func migrateToV21(conn *sql.DB) error {
	log.Info("migration v21: adding grype_db_built column to container_images")

	// Add grype_db_built column to track the vulnerability database version used for scanning
	// This stores the RFC3339 timestamp of when the grype database was built
	_, err := conn.Exec(`
		ALTER TABLE container_images ADD COLUMN grype_db_built TEXT
	`)
	if err != nil {
		return fmt.Errorf("failed to add grype_db_built column: %w", err)
	}

	log.Info("migration v21: successfully added grype_db_built column")
	log.Info("migration v21: grype_db_built stores the grype vulnerability database build timestamp used for scanning")
	return nil
}

// migrateToV22 adds job_executions table to track scheduled job execution history
func migrateToV22(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v22: creating job_executions table")

	// Create job_executions table to track job execution history
	_, err = tx.Exec(`
		CREATE TABLE job_executions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_name TEXT NOT NULL,
			started_at DATETIME NOT NULL,
			completed_at DATETIME,
			status TEXT NOT NULL DEFAULT 'running',
			error_message TEXT,
			duration_ms INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create job_executions table: %w", err)
	}

	// Create indexes for efficient querying
	_, err = tx.Exec(`
		CREATE INDEX idx_job_executions_job_name ON job_executions(job_name);
		CREATE INDEX idx_job_executions_started_at ON job_executions(started_at);
		CREATE INDEX idx_job_executions_status ON job_executions(status);
	`)
	if err != nil {
		return fmt.Errorf("failed to create job_executions indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v22: successfully created job_executions table")
	log.Info("migration v22: job_name: Name of the scheduled job")
	log.Info("migration v22: started_at: When the job started executing")
	log.Info("migration v22: completed_at: When the job finished")
	log.Info("migration v22: status: running, completed, or failed")
	log.Info("migration v22: error_message: Error details if job failed")
	log.Info("migration v22: duration_ms: Execution duration in milliseconds")
	return nil
}

// migrateToV23 adds metric_staleness table for tracking metric last-seen times
// This enables proper staleness handling for OTLP push metrics
func migrateToV23(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v23: creating metric_staleness table")

	// Create metric_staleness table with single row for JSON blob storage
	// key='metrics' stores JSON map of metric_key -> last_seen_timestamp
	_, err = tx.Exec(`
		CREATE TABLE metric_staleness (
			key TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create metric_staleness table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v23: successfully created metric_staleness table")
	log.Info("migration v23: key: Storage key (e.g., 'metrics')")
	log.Info("migration v23: data: JSON blob containing metric_key -> last_seen_timestamp map")
	log.Info("migration v23: updated_at: Last modification timestamp")
	return nil
}

// migrateToV24 adds architecture column to track CPU architecture of scanned images
// This is extracted from the SBOM (Syft) source.target metadata
func migrateToV24(conn *sql.DB) error {
	log.Info("migration v24: adding architecture column to container_images")

	// Add architecture column to track the CPU architecture (e.g., amd64, arm64)
	_, err := conn.Exec(`
		ALTER TABLE container_images ADD COLUMN architecture TEXT
	`)
	if err != nil {
		return fmt.Errorf("failed to add architecture column: %w", err)
	}

	log.Info("migration v24: successfully added architecture column")
	log.Info("migration v24: architecture: CPU architecture of the image (e.g., amd64, arm64)")
	return nil
}

// migrateToV25 populates architecture from existing SBOMs
// This extracts architecture from source.metadata.architecture in the SBOM JSON
func migrateToV25(conn *sql.DB) error {
	log.Info("migration v25: populating architecture from existing SBOMs")

	// Query all images with SBOM but no architecture
	rows, err := conn.Query(`
		SELECT id, sbom FROM container_images
		WHERE sbom IS NOT NULL AND sbom != '' AND (architecture IS NULL OR architecture = '')
	`)
	if err != nil {
		return fmt.Errorf("failed to query images: %w", err)
	}

	// Structure to extract architecture from SBOM
	type sbomSource struct {
		Metadata struct {
			Architecture string `json:"architecture"`
		} `json:"metadata"`
	}
	type sbomDoc struct {
		Source sbomSource `json:"source"`
	}

	// Collect all updates first to avoid holding rows open during updates
	type update struct {
		id   int64
		arch string
	}
	var updates []update

	for rows.Next() {
		var id int64
		var sbomJSON string
		if err := rows.Scan(&id, &sbomJSON); err != nil {
			log.Warn("migration v25: failed to scan row", "error", err)
			continue
		}

		var doc sbomDoc
		if err := json.Unmarshal([]byte(sbomJSON), &doc); err != nil {
			log.Warn("migration v25: failed to parse SBOM", "image_id", id, "error", err)
			continue
		}

		arch := doc.Source.Metadata.Architecture
		if arch != "" {
			updates = append(updates, update{id: id, arch: arch})
		}
	}
	_ = rows.Close()

	// Now apply updates
	for _, u := range updates {
		_, err = conn.Exec(`UPDATE container_images SET architecture = ? WHERE id = ?`, u.arch, u.id)
		if err != nil {
			log.Warn("migration v25: failed to update architecture", "image_id", u.id, "error", err)
			continue
		}
	}

	log.Info("migration v25: updated architecture", "images_updated", len(updates))
	return nil
}

// migrateToV26 renames metric_staleness table to app_state
// This table is now used for general application state storage, not just metric staleness
func migrateToV26(conn *sql.DB) error {
	log.Info("migration v26: renaming metric_staleness table to app_state")

	_, err := conn.Exec(`ALTER TABLE metric_staleness RENAME TO app_state`)
	if err != nil {
		return fmt.Errorf("failed to rename metric_staleness to app_state: %w", err)
	}

	log.Info("migration v26: successfully renamed metric_staleness to app_state")
	return nil
}

// migrateToV27 adds reference column to container_instances and populates it from repository+tag
// This fixes the ":latest" bug for digest-only images by preserving the original reference
func migrateToV27(conn *sql.DB) error {
	log.Info("migration v27: adding reference column to container_instances")

	// Add reference column
	_, err := conn.Exec(`ALTER TABLE container_instances ADD COLUMN reference TEXT`)
	if err != nil {
		return fmt.Errorf("failed to add reference column: %w", err)
	}

	// Populate reference from repository:tag (or just repository if tag is empty)
	_, err = conn.Exec(`
		UPDATE container_instances
		SET reference = CASE
			WHEN tag != '' THEN repository || ':' || tag
			ELSE repository
		END
	`)
	if err != nil {
		return fmt.Errorf("failed to populate reference column: %w", err)
	}

	log.Info("migration v27: successfully added and populated reference column")
	return nil
}

// migrateToV28 drops the repository and tag columns from container_instances
// This completes the migration to using reference instead of repository+tag
func migrateToV28(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v28: dropping repository and tag columns from container_instances")

	// SQLite doesn't support DROP COLUMN directly, so we need to rebuild the table
	// Step 1: Create new table without repository and tag columns
	_, err = tx.Exec(`
		CREATE TABLE container_instances_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			container TEXT NOT NULL,
			reference TEXT NOT NULL,
			image_id INTEGER NOT NULL,
			node_name TEXT,
			container_runtime TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(namespace, pod, container),
			FOREIGN KEY (image_id) REFERENCES container_images(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new instances table: %w", err)
	}

	// Step 2: Copy data from old table to new table
	_, err = tx.Exec(`
		INSERT INTO container_instances_new (id, namespace, pod, container, reference, image_id, node_name, container_runtime, created_at)
		SELECT id, namespace, pod, container, reference, image_id, node_name, container_runtime, created_at
		FROM container_instances
	`)
	if err != nil {
		return fmt.Errorf("failed to copy instances data: %w", err)
	}

	// Step 3: Drop old table
	_, err = tx.Exec(`DROP TABLE container_instances`)
	if err != nil {
		return fmt.Errorf("failed to drop old instances table: %w", err)
	}

	// Step 4: Rename new table
	_, err = tx.Exec(`ALTER TABLE container_instances_new RENAME TO container_instances`)
	if err != nil {
		return fmt.Errorf("failed to rename instances table: %w", err)
	}

	// Step 5: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX idx_instances_namespace ON container_instances(namespace);
		CREATE INDEX idx_instances_image ON container_instances(image_id);
		CREATE INDEX idx_instances_created_at ON container_instances(created_at);
	`)
	if err != nil {
		return fmt.Errorf("failed to create instances indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v28: successfully dropped repository and tag columns")
	return nil
}

// migrateToV29 renames tables and columns to match Docker/Kubernetes terminology
// container_images → images, container_instances → containers, containers.container → containers.name
func migrateToV29(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v29: renaming tables to match Docker/Kubernetes terminology")

	// Step 1: Rename container_images to images
	log.Info("migration v29: renaming container_images → images")
	_, err = tx.Exec(`ALTER TABLE container_images RENAME TO images`)
	if err != nil {
		return fmt.Errorf("failed to rename container_images to images: %w", err)
	}

	// Step 2: Create new containers table with 'name' column instead of 'container'
	log.Info("migration v29: creating containers table with renamed column")
	_, err = tx.Exec(`
		CREATE TABLE containers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			namespace TEXT NOT NULL,
			pod TEXT NOT NULL,
			name TEXT NOT NULL,
			reference TEXT NOT NULL,
			image_id INTEGER NOT NULL,
			node_name TEXT,
			container_runtime TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(namespace, pod, name),
			FOREIGN KEY (image_id) REFERENCES images(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create containers table: %w", err)
	}

	// Step 3: Copy data from container_instances to containers
	log.Info("migration v29: copying data to containers table")
	_, err = tx.Exec(`
		INSERT INTO containers (id, namespace, pod, name, reference, image_id, node_name, container_runtime, created_at)
		SELECT id, namespace, pod, container, reference, image_id, node_name, container_runtime, created_at
		FROM container_instances
	`)
	if err != nil {
		return fmt.Errorf("failed to copy data to containers table: %w", err)
	}

	// Step 4: Drop old container_instances table
	_, err = tx.Exec(`DROP TABLE container_instances`)
	if err != nil {
		return fmt.Errorf("failed to drop container_instances table: %w", err)
	}

	// Step 5: Create indexes on new containers table
	_, err = tx.Exec(`
		CREATE INDEX idx_containers_namespace ON containers(namespace);
		CREATE INDEX idx_containers_image ON containers(image_id);
		CREATE INDEX idx_containers_created_at ON containers(created_at);
	`)
	if err != nil {
		return fmt.Errorf("failed to create containers indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v29: successfully renamed tables and columns")
	log.Info("migration v29: container_images → images")
	log.Info("migration v29: container_instances → containers")
	log.Info("migration v29: containers.container → containers.name")
	return nil
}

// migrateToV30 adds nodes, node_packages, and node_vulnerabilities tables
// This enables host-level vulnerability scanning for Kubernetes nodes
func migrateToV30(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v30: creating nodes tables for host-level scanning")

	// Step 1: Create nodes table
	_, err = tx.Exec(`
		CREATE TABLE nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			hostname TEXT,
			os_release TEXT,
			kernel_version TEXT,
			architecture TEXT,
			container_runtime TEXT,
			kubelet_version TEXT,
			status TEXT DEFAULT 'pending',
			status_error TEXT,
			sbom_scanned_at DATETIME,
			vulns_scanned_at DATETIME,
			grype_db_built TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create nodes table: %w", err)
	}

	// Step 2: Create node_packages table
	_, err = tx.Exec(`
		CREATE TABLE node_packages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL REFERENCES nodes(id),
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			type TEXT NOT NULL,
			language TEXT,
			purl TEXT,
			details TEXT,
			UNIQUE(node_id, name, version, type)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_packages table: %w", err)
	}

	// Step 3: Create node_vulnerabilities table
	_, err = tx.Exec(`
		CREATE TABLE node_vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL REFERENCES nodes(id),
			package_id INTEGER NOT NULL REFERENCES node_packages(id),
			cve_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			score REAL,
			fix_status TEXT,
			fix_version TEXT,
			known_exploited BOOLEAN DEFAULT FALSE,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerabilities table: %w", err)
	}

	// Step 4: Create indexes for efficient queries
	_, err = tx.Exec(`
		CREATE INDEX idx_nodes_status ON nodes(status);
		CREATE INDEX idx_node_packages_node ON node_packages(node_id);
		CREATE INDEX idx_node_packages_name ON node_packages(name);
		CREATE INDEX idx_node_vulnerabilities_node ON node_vulnerabilities(node_id);
		CREATE INDEX idx_node_vulnerabilities_cve ON node_vulnerabilities(cve_id);
		CREATE INDEX idx_node_vulnerabilities_severity ON node_vulnerabilities(severity);
	`)
	if err != nil {
		return fmt.Errorf("failed to create node indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v30: successfully created nodes tables")
	log.Info("migration v30: nodes: Tracks Kubernetes nodes with OS/kernel info")
	log.Info("migration v30: node_packages: Packages installed on each node")
	log.Info("migration v30: node_vulnerabilities: Vulnerabilities found on nodes")
	return nil
}

// migrateToV31 adds performance indexes for node queries
// Critical: idx_node_vulnerabilities_package is required for fast SBOM view (package vulnerability counts)
func migrateToV31(conn *sql.DB) error {
	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	log.Info("migration v31: adding performance indexes for node queries")

	// Critical index: package_id for counting vulnerabilities per package in SBOM view
	// Without this index, GetNodePackages() takes 50+ seconds with ~1000 packages and ~30000 vulns
	log.Info("migration v31: creating index on node_vulnerabilities(package_id)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_node_vulnerabilities_package ON node_vulnerabilities(package_id)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerabilities package_id index: %w", err)
	}

	// Composite index for efficient severity counts per node (used in summary queries)
	log.Info("migration v31: creating composite index on node_vulnerabilities(node_id, severity)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_node_vulnerabilities_node_severity ON node_vulnerabilities(node_id, severity)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerabilities node_severity composite index: %w", err)
	}

	// Index for fix_status filtering in node summary queries
	log.Info("migration v31: creating index on node_vulnerabilities(fix_status)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_node_vulnerabilities_fix_status ON node_vulnerabilities(fix_status)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerabilities fix_status index: %w", err)
	}

	// Index for package type filtering
	log.Info("migration v31: creating index on node_packages(type)")
	_, err = tx.Exec(`
		CREATE INDEX IF NOT EXISTS idx_node_packages_type ON node_packages(type)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_packages type index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v31: successfully added performance indexes for node queries")
	log.Info("migration v31: node_vulnerabilities(package_id): Critical for SBOM view performance")
	log.Info("migration v31: node_vulnerabilities(node_id, severity): Optimizes summary counts")
	log.Info("migration v31: node_vulnerabilities(fix_status): Enables fast fix status filtering")
	log.Info("migration v31: node_packages(type): Enables fast package type filtering")
	return nil
}

// migrateToV32 adds number_of_instances column to node_packages table
// This tracks how many times the same package (name+version+type) appears in different locations
func migrateToV32(conn *sql.DB) error {
	log.Info("migration v32: adding number_of_instances column to node_packages")

	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Add number_of_instances column with default value of 1
	_, err = tx.Exec(`
		ALTER TABLE node_packages ADD COLUMN number_of_instances INTEGER DEFAULT 1
	`)
	if err != nil {
		return fmt.Errorf("failed to add number_of_instances column: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v32: successfully added number_of_instances column to node_packages")
	log.Info("migration v32: existing packages default to 1 instance")
	log.Info("migration v32: future SBOM imports will count actual instances")
	return nil
}

// migrateToV33 adds count column and UNIQUE constraint to node_vulnerabilities for deduplication
func migrateToV33(conn *sql.DB) error {
	log.Info("migration v33: adding deduplication support to node_vulnerabilities")

	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Step 1: Create new table with count column and UNIQUE constraint
	_, err = tx.Exec(`
		CREATE TABLE node_vulnerabilities_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id INTEGER NOT NULL REFERENCES nodes(id),
			package_id INTEGER NOT NULL REFERENCES node_packages(id),
			cve_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			score REAL,
			fix_status TEXT,
			fix_version TEXT,
			known_exploited BOOLEAN DEFAULT FALSE,
			count INTEGER DEFAULT 1,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(node_id, package_id, cve_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create new node_vulnerabilities table: %w", err)
	}

	// Step 2: Migrate existing data, aggregating duplicates
	_, err = tx.Exec(`
		INSERT INTO node_vulnerabilities_new (node_id, package_id, cve_id, severity, score, fix_status, fix_version, known_exploited, count, details, created_at)
		SELECT node_id, package_id, cve_id, severity, MAX(score), fix_status, fix_version, MAX(known_exploited), COUNT(*), details, MIN(created_at)
		FROM node_vulnerabilities
		GROUP BY node_id, package_id, cve_id
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate node_vulnerabilities data: %w", err)
	}

	// Step 3: Drop old table and rename new one
	_, err = tx.Exec(`DROP TABLE node_vulnerabilities`)
	if err != nil {
		return fmt.Errorf("failed to drop old node_vulnerabilities table: %w", err)
	}

	_, err = tx.Exec(`ALTER TABLE node_vulnerabilities_new RENAME TO node_vulnerabilities`)
	if err != nil {
		return fmt.Errorf("failed to rename node_vulnerabilities table: %w", err)
	}

	// Step 4: Recreate indexes
	_, err = tx.Exec(`
		CREATE INDEX idx_node_vulnerabilities_node ON node_vulnerabilities(node_id);
		CREATE INDEX idx_node_vulnerabilities_package ON node_vulnerabilities(package_id);
		CREATE INDEX idx_node_vulnerabilities_node_severity ON node_vulnerabilities(node_id, severity);
		CREATE INDEX idx_node_vulnerabilities_fix_status ON node_vulnerabilities(fix_status)
	`)
	if err != nil {
		return fmt.Errorf("failed to recreate indexes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v33: successfully added deduplication support to node_vulnerabilities")
	log.Info("migration v33: added count column (default 1)")
	log.Info("migration v33: added UNIQUE constraint on (node_id, package_id, cve_id)")
	log.Info("migration v33: existing duplicates aggregated")
	return nil
}

// migrateToV34 adds node_vulnerability_details and node_package_details tables
// This separates heavy JSON details from main tables for better performance
func migrateToV34(conn *sql.DB) error {
	log.Info("migration v34: creating node detail tables")

	tx, err := conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Create node_vulnerability_details table
	_, err = tx.Exec(`
		CREATE TABLE node_vulnerability_details (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_vulnerability_id INTEGER NOT NULL,
			details TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_vulnerability_id) REFERENCES node_vulnerabilities(id) ON DELETE CASCADE,
			UNIQUE(node_vulnerability_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerability_details table: %w", err)
	}

	// Create index for fast lookups
	_, err = tx.Exec(`
		CREATE INDEX idx_node_vulnerability_details_vuln ON node_vulnerability_details(node_vulnerability_id)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_vulnerability_details index: %w", err)
	}

	// Create node_package_details table
	_, err = tx.Exec(`
		CREATE TABLE node_package_details (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_package_id INTEGER NOT NULL,
			details TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (node_package_id) REFERENCES node_packages(id) ON DELETE CASCADE,
			UNIQUE(node_package_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_package_details table: %w", err)
	}

	// Create index for fast lookups
	_, err = tx.Exec(`
		CREATE INDEX idx_node_package_details_pkg ON node_package_details(node_package_id)
	`)
	if err != nil {
		return fmt.Errorf("failed to create node_package_details index: %w", err)
	}

	// Migrate existing details from node_vulnerabilities to node_vulnerability_details
	_, err = tx.Exec(`
		INSERT INTO node_vulnerability_details (node_vulnerability_id, details)
		SELECT id, details FROM node_vulnerabilities
		WHERE details IS NOT NULL AND details != ''
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate node vulnerability details: %w", err)
	}

	// Migrate existing details from node_packages to node_package_details
	_, err = tx.Exec(`
		INSERT INTO node_package_details (node_package_id, details)
		SELECT id, details FROM node_packages
		WHERE details IS NOT NULL AND details != ''
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate node package details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("migration v34: successfully created node detail tables")
	log.Info("migration v34: created node_vulnerability_details table")
	log.Info("migration v34: created node_package_details table")
	log.Info("migration v34: migrated existing details data")
	return nil
}

// migrateToV35 adds sbom and vulnerabilities columns to nodes table for storing raw JSON
// This enables the /api/nodes/{name}/sbom and /api/nodes/{name}/vulnerabilities endpoints
// to return the full Syft and Grype output respectively
func migrateToV35(conn *sql.DB) error {
	log.Info("migration v35: adding sbom and vulnerabilities columns to nodes table")

	_, err := conn.Exec(`ALTER TABLE nodes ADD COLUMN sbom TEXT`)
	if err != nil {
		return fmt.Errorf("failed to add sbom column to nodes: %w", err)
	}

	_, err = conn.Exec(`ALTER TABLE nodes ADD COLUMN vulnerabilities TEXT`)
	if err != nil {
		return fmt.Errorf("failed to add vulnerabilities column to nodes: %w", err)
	}

	log.Info("migration v35: successfully added sbom and vulnerabilities columns to nodes table")
	log.Info("migration v35: sbom: Stores raw SBOM JSON from Syft")
	log.Info("migration v35: vulnerabilities: Stores raw vulnerability JSON from Grype")
	return nil
}

// migrateToV36 creates a dedicated metric_staleness table with per-metric-key rows.
// This replaces the single JSON blob stored in app_state (key="metrics"), which
// doesn't scale beyond ~10k metric keys (~65MB blob at current scale, ~420MB at 10x).
// The new table uses SQLite's PRIMARY KEY index for O(1) upserts and a separate
// last_seen_unix index for efficient stale-entry queries.
func migrateToV36(conn *sql.DB) error {
	log.Info("migration v36: creating metric_staleness table for scalable per-metric staleness tracking")

	_, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS metric_staleness (
			metric_key      TEXT PRIMARY KEY,
			family_name     TEXT NOT NULL,
			labels_json     TEXT NOT NULL,
			last_seen_unix  INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_metric_staleness_last_seen ON metric_staleness(last_seen_unix);
	`)
	if err != nil {
		return fmt.Errorf("failed to create metric_staleness table: %w", err)
	}

	log.Info("migration v36: successfully created metric_staleness table")
	return nil
}
