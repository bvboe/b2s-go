package database

import (
	"database/sql"
	"fmt"
)

// QueryInstances executes a query and returns rows for instance metrics
func (db *DB) QueryInstances(query string) (*sql.Rows, error) {
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query instances: %w", err)
	}
	return rows, nil
}

// QueryVulnerabilityDetails executes a query and returns rows for individual CVE metrics per container
func (db *DB) QueryVulnerabilityDetails(query string) (*sql.Rows, error) {
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability details: %w", err)
	}
	return rows, nil
}

// QueryPackageDetails executes a query and returns rows for individual package metrics per container
func (db *DB) QueryPackageDetails(query string) (*sql.Rows, error) {
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query package details: %w", err)
	}
	return rows, nil
}
