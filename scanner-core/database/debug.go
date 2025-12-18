package database

import (
	"fmt"
	"log"
	"time"
)

// QueryResult represents the result of a SQL query with column order preserved.
type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
}

// ExecuteReadOnlyQuery executes a read-only SQL query and returns results with column order preserved.
// The QueryResult includes both an ordered columns array and row data as maps.
//
// This method is intended for debug/diagnostic purposes only and should only be called
// from the debug SQL handler after proper validation.
//
// WARNING: This method does NOT validate the SQL query. The caller MUST ensure the query
// is safe before calling this method. Use debug.IsSelectQuery() to validate queries.
func (db *DB) ExecuteReadOnlyQuery(query string) (*QueryResult, error) {
	// Log the SQL query for tracking
	log.Printf("[DEBUG SQL] Executing query: %s", query)
	start := time.Now()

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Log but don't fail on close error
			fmt.Printf("Warning: Failed to close rows: %v\n", err)
		}
	}()

	// Get column names (preserves database order)
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Build result set
	var results []map[string]interface{}

	for rows.Next() {
		// Create slice for scanning
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row into value pointers
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Build map for this row
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]

			// Convert []byte to string for better JSON serialization
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}

		results = append(results, row)
	}

	// Check for errors from iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	// Log completion with row count and duration
	duration := time.Since(start)
	log.Printf("[DEBUG SQL] Query completed: %d rows returned in %v", len(results), duration)

	return &QueryResult{
		Columns: columns,
		Rows:    results,
	}, nil
}
