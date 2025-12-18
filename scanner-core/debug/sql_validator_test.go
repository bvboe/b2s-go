package debug

import (
	"testing"
)

func TestIsSelectQuery_ValidQueries(t *testing.T) {
	validQueries := []string{
		"SELECT * FROM images",
		"select * from images",
		"  SELECT * FROM images  ",
		"SELECT id, name FROM images WHERE id = 1",
		"SELECT COUNT(*) FROM images",
		"SELECT * FROM images LIMIT 10",
		"SELECT * FROM images ORDER BY created_at DESC",
		"SELECT i.*, p.name FROM images i JOIN packages p ON i.id = p.image_id",
		"SELECT * FROM images WHERE digest = 'sha256:abc123'",
		"-- This is a comment\nSELECT * FROM images",
		"SELECT * FROM images -- comment at end",
		// Queries with single trailing semicolon (standard SQL convention)
		"SELECT * FROM images;",
		"SELECT * FROM images LIMIT 10;",
		"DESCRIBE images;",
		"EXPLAIN QUERY PLAN SELECT * FROM images;",
		"PRAGMA table_info(images);",
	}

	for _, query := range validQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if !valid {
				t.Errorf("Expected query to be valid, got error: %v", err)
			}
		})
	}
}

func TestIsSelectQuery_InvalidStart(t *testing.T) {
	invalidQueries := []string{
		"INSERT INTO images VALUES (1, 'test')",
		"UPDATE images SET name = 'test'",
		"DELETE FROM images",
		"DROP TABLE images",
		"CREATE TABLE images (id INT)",
		"ALTER TABLE images ADD COLUMN name VARCHAR(255)",
		"TRUNCATE TABLE images",
		"",
		"  ",
		"-- just a comment",
	}

	for _, query := range invalidQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if valid {
				t.Errorf("Expected query to be invalid: %s", query)
			}
			if err == nil {
				t.Error("Expected error for invalid query")
			}
		})
	}
}

func TestIsSelectQuery_MultipleStatements(t *testing.T) {
	// Queries with multiple statements should be blocked
	invalidQueries := []string{
		"SELECT * FROM images; DROP TABLE images;",
		"SELECT * FROM images; DROP TABLE images",
		"SELECT * FROM images;DROP TABLE images",
		"SELECT id FROM images; SELECT * FROM users",
		// Semicolons in string literals are also blocked (overly strict but acceptable for security)
		"SELECT * FROM images WHERE name = 'test;123'",
		"SELECT * FROM images WHERE desc = 'foo;bar;baz'",
	}

	for _, query := range invalidQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if valid {
				t.Errorf("Expected query with multiple statements to be invalid: %s", query)
			}
			if err == nil {
				t.Error("Expected error for query with multiple statements")
			}
			if err != nil && err.Error() != "multiple statements not allowed" {
				t.Errorf("Expected 'multiple statements not allowed' error, got: %v", err)
			}
		})
	}
}

func TestIsSelectQuery_DangerousKeywords(t *testing.T) {
	dangerousQueries := []string{
		"SELECT * FROM images WHERE 1=1; INSERT INTO images VALUES (1)",
		"SELECT * FROM images; UPDATE images SET name = 'hack'",
		"SELECT * FROM images; DELETE FROM images",
		"SELECT * FROM images; DROP TABLE images",
		"SELECT * FROM images; CREATE TABLE hack (id INT)",
		"SELECT * FROM images; ALTER TABLE images DROP COLUMN name",
		"SELECT * FROM images; TRUNCATE TABLE images",
	}

	for _, query := range dangerousQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if valid {
				t.Errorf("Expected dangerous query to be invalid: %s", query)
			}
			if err == nil {
				t.Error("Expected error for dangerous query")
			}
		})
	}
}

func TestIsSelectQuery_FalsePositives(t *testing.T) {
	// These should be valid - they contain substrings of dangerous keywords
	// but not the actual keywords as whole words
	validQueries := []string{
		"SELECT deleted_at FROM images",           // Contains "DELETE" substring
		"SELECT updated_at FROM images",           // Contains "UPDATE" substring
		"SELECT description FROM images",          // Contains "script" substring
		"SELECT created_at, updated_at FROM images",
		"SELECT dropbox_url FROM images",          // Contains "DROP" substring
	}

	for _, query := range validQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if !valid {
				t.Errorf("Expected query to be valid (false positive check), got error: %v\nQuery: %s", err, query)
			}
		})
	}
}

func TestIsSelectQuery_EmptyQuery(t *testing.T) {
	valid, err := IsSelectQuery("")
	if valid {
		t.Error("Expected empty query to be invalid")
	}
	if err == nil {
		t.Error("Expected error for empty query")
	}
	if err.Error() != "empty query" {
		t.Errorf("Expected 'empty query' error, got: %v", err)
	}
}

func TestIsSelectQuery_CaseInsensitive(t *testing.T) {
	queries := []string{
		"SELECT * FROM images",
		"select * from images",
		"SeLeCt * FrOm images",
		"  SELECT * FROM images  ",
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			valid, err := IsSelectQuery(query)
			if !valid {
				t.Errorf("Expected case-insensitive SELECT to be valid, got error: %v", err)
			}
		})
	}
}

func TestIsSelectQuery_Comments(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		valid   bool
	}{
		{
			name:  "Comment before SELECT",
			query: "-- Get all images\nSELECT * FROM images",
			valid: true,
		},
		{
			name:  "Comment after SELECT",
			query: "SELECT * FROM images -- all images",
			valid: true,
		},
		{
			name:  "Comment with dangerous keyword",
			query: "SELECT * FROM images -- DROP TABLE would be bad",
			valid: true,
		},
		{
			name:  "Multiple comment lines",
			query: "-- First comment\n-- Second comment\nSELECT * FROM images",
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := IsSelectQuery(tt.query)
			if valid != tt.valid {
				t.Errorf("Expected valid=%v, got valid=%v, error: %v", tt.valid, valid, err)
			}
		})
	}
}

func TestContainsKeyword(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		keyword  string
		expected bool
	}{
		{"Keyword in middle with spaces", "SELECT * FROM images DELETE FROM users", "DELETE", true},
		{"Keyword at start", "DELETE FROM images", "DELETE", true},
		{"Keyword at end", "SELECT * FROM images WHERE action = DROP", "DROP", true},
		{"Keyword with parenthesis", "SELECT * FROM images WHERE DELETE()", "DELETE", true},
		{"Keyword as substring", "SELECT deleted_at FROM images", "DELETE", false},
		{"Keyword with newline", "SELECT * FROM images\nDELETE FROM users", "DELETE", true},
		{"Keyword with tab", "SELECT * FROM images\tDELETE FROM users", "DELETE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsKeyword(tt.sql, tt.keyword)
			if result != tt.expected {
				t.Errorf("containsKeyword(%q, %q) = %v, expected %v", tt.sql, tt.keyword, result, tt.expected)
			}
		})
	}
}
