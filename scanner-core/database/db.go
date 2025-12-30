package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
)

// DB wraps the database connection
type DB struct {
	conn *sql.DB
}

// GetConnection returns the underlying database connection (for testing)
func (db *DB) GetConnection() *sql.DB {
	return db.conn
}

// isCorruptionError checks if an error indicates database corruption
func isCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "malformed") ||
		strings.Contains(errMsg, "corrupt") ||
		strings.Contains(errMsg, "database disk image is malformed")
}

// deleteDatabase deletes the database file and associated files (WAL, SHM)
func deleteDatabase(dbPath string) error {
	log.Printf("Deleting database files at %s", dbPath)

	// Delete main database file
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete database file: %w", err)
	}

	// Delete WAL file if exists
	walPath := dbPath + "-wal"
	if err := os.Remove(walPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to delete WAL file: %v", err)
	}

	// Delete SHM file if exists
	shmPath := dbPath + "-shm"
	if err := os.Remove(shmPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to delete SHM file: %v", err)
	}

	log.Printf("Database files deleted, will create fresh database")
	return nil
}

// New creates a new database connection
// If the database is corrupted, it will be deleted and recreated
func New(dbPath string) (*DB, error) {
	// Try to open the database
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection and check for corruption
	if err := conn.Ping(); err != nil {
		_ = conn.Close()

		// Check if it's a corruption error
		if isCorruptionError(err) {
			log.Printf("Database corruption detected: %v", err)
			log.Printf("Deleting corrupted database and starting fresh...")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}

			// Try again with fresh database
			conn, err = sql.Open("sqlite", dbPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create new database: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to ping database: %w", err)
		}
	}

	// Configure connection pool for SQLite
	conn.SetMaxOpenConns(1) // SQLite works best with a single connection
	conn.SetMaxIdleConns(1)

	// Configure SQLite for better concurrency
	_, err = conn.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 5000;
		PRAGMA synchronous = NORMAL;
	`)
	if err != nil {
		_ = conn.Close()

		// If configuration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Printf("Database corruption detected during configuration: %v", err)
			log.Printf("Deleting corrupted database and starting fresh...")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	db := &DB{conn: conn}

	// Run migrations to ensure schema is up to date
	if err := db.ensureSchemaVersion(); err != nil {
		_ = conn.Close()

		// If migration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Printf("Database corruption detected during migration: %v", err)
			log.Printf("Deleting corrupted database and starting fresh...")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	log.Printf("Database initialized at %s", dbPath)
	return db, nil
}

// Close closes the database connection gracefully
func Close(db *DB) error {
	if db == nil || db.conn == nil {
		return nil
	}

	// Checkpoint WAL to ensure all data is written to main database
	log.Printf("Checkpointing WAL before closing database...")
	if _, err := db.conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Printf("Warning: failed to checkpoint WAL: %v", err)
	}

	return db.conn.Close()
}

// HealthCheck performs a database integrity check
// Returns nil if database is healthy, error if corrupted
func HealthCheck(db *DB) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("database connection is nil")
	}

	// Quick check: can we query the database?
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM sqlite_master").Scan(&count)
	if err != nil {
		return fmt.Errorf("database query failed: %w", err)
	}

	// Deep check: integrity check (expensive, use sparingly)
	// Uncomment if you want to run on startup or periodically
	/*
	var result string
	err = db.conn.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}
	*/

	return nil
}

// RecoverFromCorruption attempts to recover from database corruption
// WARNING: This may result in data loss
func RecoverFromCorruption(dbPath string) error {
	log.Printf("Attempting to recover corrupted database at %s", dbPath)

	// Try to dump and restore
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open corrupted database: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Attempt to export data to a new database
	backupPath := dbPath + ".backup"
	log.Printf("Creating backup at %s", backupPath)

	_, err = conn.Exec(fmt.Sprintf("VACUUM INTO '%s'", backupPath))
	if err != nil {
		log.Printf("VACUUM INTO failed: %v", err)
		// Try alternative recovery: .dump equivalent
		return fmt.Errorf("failed to recover database: %w", err)
	}

	log.Printf("Database recovered to %s", backupPath)
	log.Printf("To use recovered database, run: mv %s %s", backupPath, dbPath)

	return nil
}
