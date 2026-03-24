package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentDatabase)

// DB wraps the database connection.
// writeMu serializes all write transactions at the Go level so that SQLite
// never receives a concurrent write and SQLITE_BUSY is impossible.
type DB struct {
	writeMu sync.Mutex
	conn    *sql.DB
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

// exitOnCorruption exits the process when a corruption error is detected during a
// write operation. The pod will be restarted by Kubernetes, and the startup integrity
// check in New() will delete the corrupt database and reinitialize from scratch.
func exitOnCorruption(err error) {
	if isCorruptionError(err) {
		log.Error("fatal: database corruption detected during write, exiting for pod restart", slog.Any("error", err))
		os.Exit(1)
	}
}

// deleteDatabase deletes the database file and associated files (WAL, SHM)
func deleteDatabase(dbPath string) error {
	log.Info("deleting database files", "path", dbPath)

	// Delete main database file
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete database file: %w", err)
	}

	// Delete WAL file if exists
	walPath := dbPath + "-wal"
	if err := os.Remove(walPath); err != nil && !os.IsNotExist(err) {
		log.Warn("failed to delete WAL file", slog.Any("error", err))
	}

	// Delete SHM file if exists
	shmPath := dbPath + "-shm"
	if err := os.Remove(shmPath); err != nil && !os.IsNotExist(err) {
		log.Warn("failed to delete SHM file", slog.Any("error", err))
	}

	log.Info("database files deleted, will create fresh database")
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
			log.Error("database corruption detected", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
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

	// Run a quick integrity check to catch corruption that doesn't fail Ping().
	// A corrupt SQLite file can still accept connections but fail on reads/writes.
	// quick_check is much faster than integrity_check and catches the common cases.
	var quickCheckResult string
	if err := conn.QueryRow("PRAGMA quick_check").Scan(&quickCheckResult); err != nil || quickCheckResult != "ok" {
		_ = conn.Close()
		log.Error("database failed integrity check on startup, deleting and starting fresh",
			"result", quickCheckResult, slog.Any("error", err))
		if err := deleteDatabase(dbPath); err != nil {
			return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
		}
		return New(dbPath)
	}

	// Configure connection pool for SQLite.
	// 2 connections: one for long-running streaming reads, one for concurrent writes
	// (e.g. staleness upserts during /metrics streaming). WAL mode supports this.
	conn.SetMaxOpenConns(2)
	conn.SetMaxIdleConns(2)

	// Configure SQLite for better concurrency
	_, err = conn.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 30000;
		PRAGMA synchronous = NORMAL;
	`)
	if err != nil {
		_ = conn.Close()

		// If configuration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Error("database corruption detected during configuration", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	db := &DB{conn: conn}

	// Checkpoint WAL on startup to merge any writes from before an unclean shutdown
	// (e.g. OOM kill). Without this the WAL can grow to the same size as the main DB
	// and every query must replay the entire WAL, causing severe slowdowns.
	// TRUNCATE resets the WAL to zero bytes after checkpointing.
	// Safe at startup: the previous pod is dead so no other writer is active.
	var walBusy, walLog, walCheckpointed int
	if err := conn.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&walBusy, &walLog, &walCheckpointed); err != nil {
		log.Warn("startup WAL checkpoint failed", slog.Any("error", err))
	} else if walLog > 0 {
		log.Info("startup WAL checkpoint complete", "wal_frames", walLog, "checkpointed", walCheckpointed, "busy", walBusy == 1)
	}

	// Run migrations to ensure schema is up to date
	if err := db.ensureSchemaVersion(); err != nil {
		_ = conn.Close()

		// If migration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Error("database corruption detected during migration", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	log.Info("database initialized", "path", dbPath)
	return db, nil
}

// ResetInterruptedScans resets any nodes or images left in transient scan states
// back to pending. This happens when the server crashes or is OOM-killed mid-scan.
// Should be called once at startup, before the scan queue and watchers are started.
func (db *DB) ResetInterruptedScans() error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()

	res, err := db.conn.Exec(`
		UPDATE nodes SET status = 'pending', status_error = ''
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
	`)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to reset interrupted node scans: %w", err)
	}
	nodeRows, _ := res.RowsAffected()

	res, err = db.conn.Exec(`
		UPDATE images SET status = 'pending'
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
	`)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to reset interrupted image scans: %w", err)
	}
	imageRows, _ := res.RowsAffected()

	if nodeRows > 0 || imageRows > 0 {
		log.Warn("reset interrupted scans to pending on startup",
			"nodes", nodeRows, "images", imageRows)
	}
	return nil
}

// Close closes the database connection gracefully
func Close(db *DB) error {
	if db == nil || db.conn == nil {
		return nil
	}

	// Checkpoint WAL to ensure all data is written to main database
	log.Info("checkpointing WAL before closing database")
	if _, err := db.conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Warn("failed to checkpoint WAL", "error", err)
	}

	return db.conn.Close()
}

// walUnmergedFramesLimit is the number of unmerged WAL frames above which the
// WAL monitor will emit a warning. Each frame is 4096 bytes (default page size),
// so 500,000 frames ≈ 2GB of unmerged WAL — clearly stuck, not just slow.
const walUnmergedFramesLimit = 500_000

// HealthCheck checks whether the database connection is responsive.
// It uses SELECT 1 to avoid write I/O (PRAGMA wal_checkpoint) competing with
// active scan jobs on slow NFS, which caused false-positive liveness probe failures.
// WAL accumulation is monitored separately by StartWALMonitor.
func HealthCheck(db *DB) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("database connection is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var v int
	if err := db.conn.QueryRowContext(ctx, "SELECT 1").Scan(&v); err != nil {
		return fmt.Errorf("database unresponsive: %w", err)
	}
	return nil
}

// StartWALMonitor runs a background goroutine that periodically checks WAL size
// and logs a warning if unmerged frames exceed walUnmergedFramesLimit (~2GB).
// This is separate from HealthCheck so slow NFS I/O does not cause false-positive
// liveness probe failures. The goroutine exits when ctx is cancelled.
func StartWALMonitor(ctx context.Context, db *DB) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if db == nil || db.conn == nil {
					return
				}
				checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				var busy, walLog, checkpointed int
				err := db.conn.QueryRowContext(checkCtx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &walLog, &checkpointed)
				cancel()
				if err != nil {
					log.Warn("WAL monitor: checkpoint query failed", slog.Any("error", err))
					continue
				}
				unmerged := walLog - checkpointed
				if unmerged > walUnmergedFramesLimit {
					log.Warn("WAL monitor: WAL too large, checkpointing may be broken",
						"wal_frames", walLog, "unmerged", unmerged,
						"unmerged_mb", unmerged*4096/1024/1024)
				} else if walLog > 0 {
					log.Debug("WAL monitor: checkpoint ok", "wal_frames", walLog, "checkpointed", checkpointed, "unmerged", unmerged)
				}
			}
		}
	}()
}

// RecoverFromCorruption attempts to recover from database corruption
// WARNING: This may result in data loss
func RecoverFromCorruption(dbPath string) error {
	log.Info("attempting to recover corrupted database", "path", dbPath)

	// Try to dump and restore
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open corrupted database: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Attempt to export data to a new database
	backupPath := dbPath + ".backup"
	log.Info("creating backup", "path", backupPath)

	_, err = conn.Exec(fmt.Sprintf("VACUUM INTO '%s'", backupPath))
	if err != nil {
		log.Error("VACUUM INTO failed", "error", err)
		// Try alternative recovery: .dump equivalent
		return fmt.Errorf("failed to recover database: %w", err)
	}

	log.Info("database recovered", "backup_path", backupPath)
	log.Info("to use recovered database, run command", "command", fmt.Sprintf("mv %s %s", backupPath, dbPath))

	return nil
}
