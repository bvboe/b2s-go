package debug

import (
	"fmt"
	"strings"
)

// dangerousKeywords are SQL keywords that should not be allowed in debug queries.
var dangerousKeywords = []string{
	"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
	"TRUNCATE", "REPLACE", "GRANT", "REVOKE",
	"EXEC", "EXECUTE",
}

// allowedStatements are read-only SQL statement types that are safe for debug queries.
var allowedStatements = []string{
	"SELECT", "DESCRIBE", "DESC", "EXPLAIN", "PRAGMA", "SHOW",
}

// IsSelectQuery validates that a SQL query is a safe read-only statement.
// It returns true if the query is valid, false otherwise, along with an error
// describing any validation failure.
//
// Validation rules:
//  1. Query must start with an allowed read-only statement (SELECT, DESCRIBE, EXPLAIN, PRAGMA, etc.)
//  2. A single trailing semicolon is allowed, but multiple statements are prevented
//  3. Query must not contain dangerous keywords (INSERT, UPDATE, DELETE, etc.)
func IsSelectQuery(sql string) (bool, error) {
	if sql == "" {
		return false, fmt.Errorf("empty query")
	}

	// Trim whitespace and normalize to uppercase for checking
	trimmed := strings.TrimSpace(sql)

	// Allow a single trailing semicolon but strip it for validation
	// This prevents multiple statements while allowing standard SQL convention
	if strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(trimmed[:len(trimmed)-1])
	}

	// Check for semicolons after stripping trailing one (prevents multiple statements)
	if strings.Contains(trimmed, ";") {
		return false, fmt.Errorf("multiple statements not allowed")
	}

	upper := strings.ToUpper(trimmed)

	// Remove single-line comments (--) for validation
	// Multi-line comments (/* */) are kept as they might be part of the query
	lines := strings.Split(upper, "\n")
	var cleanedLines []string
	for _, line := range lines {
		// Remove everything after --
		if idx := strings.Index(line, "--"); idx != -1 {
			line = line[:idx]
		}
		cleanedLines = append(cleanedLines, line)
	}
	upper = strings.Join(cleanedLines, "\n")
	upper = strings.TrimSpace(upper)

	// Check if query starts with an allowed statement
	allowed := false
	for _, stmt := range allowedStatements {
		if strings.HasPrefix(upper, stmt) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false, fmt.Errorf("query must start with one of: %s", strings.Join(allowedStatements, ", "))
	}

	// Check for dangerous keywords
	for _, keyword := range dangerousKeywords {
		// Use word boundary checks to avoid false positives
		// For example, "SELECT" shouldn't trigger "DELETE"
		if containsKeyword(upper, keyword) {
			return false, fmt.Errorf("dangerous keyword not allowed: %s", keyword)
		}
	}

	return true, nil
}

// containsKeyword checks if the SQL contains a keyword as a whole word.
// This avoids false positives like "SELECT" containing "ELECT".
func containsKeyword(sql string, keyword string) bool {
	// Simple word boundary check using spaces
	// This catches most cases without complex regex
	patterns := []string{
		" " + keyword + " ",
		" " + keyword + "(",
		" " + keyword + "\n",
		" " + keyword + "\t",
		"\n" + keyword + " ",
		"\t" + keyword + " ",
	}

	// Also check if keyword is at start or end
	if strings.HasPrefix(sql, keyword+" ") || strings.HasPrefix(sql, keyword+"(") {
		return true
	}
	if strings.HasSuffix(sql, " "+keyword) {
		return true
	}

	for _, pattern := range patterns {
		if strings.Contains(sql, pattern) {
			return true
		}
	}

	return false
}
