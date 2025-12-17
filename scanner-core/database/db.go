package database

import (
	"database/sql"
	"fmt"
	"log"
)

// DB wraps the database connection
type DB struct {
	conn *sql.DB
}

// New creates a new database connection
func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
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
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	db := &DB{conn: conn}

	// Run migrations to ensure schema is up to date
	if err := db.ensureSchemaVersion(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	log.Printf("Database initialized at %s", dbPath)
	return db, nil
}

// Close closes the database connection
func Close(db *DB) error {
	if db != nil && db.conn != nil {
		return db.conn.Close()
	}
	return nil
}
