package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationV7WithBadNginxData(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Initialize database (this will run migrations)
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() {
		if err := Close(db); err != nil {
			t.Logf("Warning: failed to close database: %v", err)
		}
	}()

	// Verify migration v7 was applied by checking if new columns exist
	rows, err := db.conn.Query(`PRAGMA table_info(vulnerabilities)`)
	if err != nil {
		t.Fatalf("Failed to query table info: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Logf("Warning: failed to close rows: %v", err)
		}
	}()

	columnNames := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name string
		var ctype string
		var notnull int
		var dfltValue interface{}
		var pk int
		err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if err != nil {
			t.Fatalf("Failed to scan column info: %v", err)
		}
		columnNames[name] = true
	}

	// Check that new columns exist
	requiredColumns := []string{"risk", "epss_score", "epss_percentile", "known_exploited"}
	for _, col := range requiredColumns {
		if !columnNames[col] {
			t.Errorf("Column %s not found in vulnerabilities table", col)
		}
	}

	// Load bad-nginx test data
	testDataPath := "../../dev-local/test-data/bad-nginx-scanresult.json"
	vulnJSON, err := os.ReadFile(testDataPath)
	if err != nil {
		t.Skipf("Skipping test data verification: %v", err)
		return
	}

	// Create a test image to associate vulnerabilities with
	_, err = db.conn.Exec(`
		INSERT INTO container_images (digest, created_at, updated_at)
		VALUES ('sha256:test123', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	var imageID int64
	err = db.conn.QueryRow(`SELECT id FROM container_images WHERE digest = 'sha256:test123'`).Scan(&imageID)
	if err != nil {
		t.Fatalf("Failed to get image ID: %v", err)
	}

	// Parse vulnerability data
	err = parseVulnerabilityData(db.conn, imageID, vulnJSON)
	if err != nil {
		t.Fatalf("Failed to parse vulnerability data: %v", err)
	}

	// Verify that vulnerabilities were inserted with new fields
	var count int
	var hasRisk, hasEPSS, hasKnownExploited int

	err = db.conn.QueryRow(`
		SELECT
			COUNT(*),
			SUM(CASE WHEN risk > 0 THEN 1 ELSE 0 END),
			SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END),
			SUM(CASE WHEN known_exploited > 0 THEN 1 ELSE 0 END)
		FROM vulnerabilities
		WHERE image_id = ?
	`, imageID).Scan(&count, &hasRisk, &hasEPSS, &hasKnownExploited)
	if err != nil {
		t.Fatalf("Failed to query vulnerabilities: %v", err)
	}

	t.Logf("Parsed %d vulnerabilities", count)
	t.Logf("Vulnerabilities with risk > 0: %d", hasRisk)
	t.Logf("Vulnerabilities with EPSS > 0: %d", hasEPSS)
	t.Logf("Vulnerabilities with known exploits: %d", hasKnownExploited)

	if count == 0 {
		t.Error("No vulnerabilities were parsed")
	}

	if hasRisk == 0 {
		t.Error("No vulnerabilities have risk scores")
	}

	if hasEPSS == 0 {
		t.Error("No vulnerabilities have EPSS scores")
	}

	// Verify that known_exploits matches known_exploited for all vulnerabilities
	var mismatchCount int
	err = db.conn.QueryRow(`
		SELECT COUNT(*)
		FROM vulnerabilities
		WHERE image_id = ? AND known_exploits != known_exploited
	`, imageID).Scan(&mismatchCount)
	if err != nil {
		t.Fatalf("Failed to query exploit field consistency: %v", err)
	}
	if mismatchCount > 0 {
		t.Errorf("Found %d vulnerabilities where known_exploits != known_exploited", mismatchCount)
	}

	// Query a specific vulnerability with known exploit (CVE-2020-15999)
	var risk, epssScore, epssPercentile float64
	var knownExploited, knownExploits int
	var severity string

	err = db.conn.QueryRow(`
		SELECT risk, epss_score, epss_percentile, known_exploited, known_exploits, severity
		FROM vulnerabilities
		WHERE cve_id = 'CVE-2020-15999' AND image_id = ?
		LIMIT 1
	`, imageID).Scan(&risk, &epssScore, &epssPercentile, &knownExploited, &knownExploits, &severity)

	if err == nil {
		t.Logf("CVE-2020-15999: risk=%.2f, epss=%.5f, percentile=%.5f, exploited=%d, exploits=%d, severity=%s",
			risk, epssScore, epssPercentile, knownExploited, knownExploits, severity)

		if risk <= 0 {
			t.Error("CVE-2020-15999 should have risk > 0")
		}
		if epssScore <= 0 {
			t.Error("CVE-2020-15999 should have EPSS score > 0")
		}
		if knownExploited != 1 {
			t.Errorf("CVE-2020-15999 should have known_exploited=1, got %d", knownExploited)
		}
		if knownExploits != 1 {
			t.Errorf("CVE-2020-15999 should have known_exploits=1, got %d", knownExploits)
		}
		if knownExploits != knownExploited {
			t.Errorf("CVE-2020-15999: known_exploits(%d) should match known_exploited(%d)", knownExploits, knownExploited)
		}
	} else {
		t.Logf("CVE-2020-15999 not found in parsed data (might be expected depending on test data)")
	}

	// Verify at least one vulnerability has no exploits
	var noExploitCVE string
	var noExploitExploited, noExploitExploits int
	err = db.conn.QueryRow(`
		SELECT cve_id, known_exploited, known_exploits
		FROM vulnerabilities
		WHERE image_id = ? AND known_exploited = 0
		LIMIT 1
	`, imageID).Scan(&noExploitCVE, &noExploitExploited, &noExploitExploits)

	if err == nil {
		t.Logf("Found CVE with no exploits: %s (exploited=%d, exploits=%d)", noExploitCVE, noExploitExploited, noExploitExploits)
		if noExploitExploits != 0 {
			t.Errorf("CVE %s should have known_exploits=0, got %d", noExploitCVE, noExploitExploits)
		}
	} else {
		t.Logf("No CVE without exploits found (might indicate data issue)")
	}

	// Verify distro information was extracted and stored
	var osName, osVersion string
	err = db.conn.QueryRow(`
		SELECT os_name, os_version
		FROM container_images
		WHERE id = ?
	`, imageID).Scan(&osName, &osVersion)

	if err == nil {
		t.Logf("Distro info: os_name=%s, os_version=%s", osName, osVersion)
		if osName == "" {
			t.Error("os_name should not be empty")
		}
		if osVersion == "" {
			t.Error("os_version should not be empty")
		}
	} else {
		t.Errorf("Failed to query distro info: %v", err)
	}
}
