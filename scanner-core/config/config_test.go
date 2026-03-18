package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.Port != "9999" {
		t.Errorf("Expected default port 9999, got %s", cfg.Port)
	}

	if cfg.DBPath != "/var/lib/bjorn2scan/data/containers.db" {
		t.Errorf("Expected default db path, got %s", cfg.DBPath)
	}

	if cfg.DebugEnabled {
		t.Error("Expected debug disabled by default")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	configContent := `port=8080
db_path=/tmp/test.db
debug_enabled=true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify values from file
	if cfg.Port != "8080" {
		t.Errorf("Expected port 8080, got %s", cfg.Port)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected db path /tmp/test.db, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled")
	}
}

func TestLoadConfigWithEnvironmentOverrides(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	configContent := `port=8080
db_path=/tmp/test.db
debug_enabled=false
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set environment variables to override
	if err := os.Setenv("PORT", "7777"); err != nil {
		t.Fatalf("Failed to set PORT env var: %v", err)
	}
	if err := os.Setenv("DEBUG_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set DEBUG_ENABLED env var: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("PORT")
		_ = os.Unsetenv("DEBUG_ENABLED")
	}()

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify env vars override file values
	if cfg.Port != "7777" {
		t.Errorf("Expected port 7777 from env, got %s", cfg.Port)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected db path from file, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled from env")
	}
}

func TestLoadConfigNoFile(t *testing.T) {
	// Load config with non-existent file (should use defaults)
	cfg, err := LoadConfig("/nonexistent/path.conf")
	if err != nil {
		t.Fatalf("Should not error when file doesn't exist: %v", err)
	}

	// Verify defaults are used
	if cfg.Port != "9999" {
		t.Errorf("Expected default port, got %s", cfg.Port)
	}

	if cfg.DebugEnabled {
		t.Error("Expected debug disabled by default")
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	// Load with empty path (should use defaults)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config with empty path: %v", err)
	}

	// Verify defaults
	if cfg.Port != "9999" {
		t.Errorf("Expected default port, got %s", cfg.Port)
	}
}

func TestDebugEnabledVariations(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test.conf")

			configContent := "debug_enabled=" + tt.value + "\n"
			err := os.WriteFile(configPath, []byte(configContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if cfg.DebugEnabled != tt.expected {
				t.Errorf("Expected debug_enabled=%v for value %q, got %v",
					tt.expected, tt.value, cfg.DebugEnabled)
			}
		})
	}
}

func TestLoadConfigWithDefaults(t *testing.T) {
	// Save original env vars
	origPort := os.Getenv("PORT")
	origDB := os.Getenv("DB_PATH")
	origDebug := os.Getenv("DEBUG_ENABLED")

	// Set env vars for testing
	if err := os.Setenv("PORT", "5555"); err != nil {
		t.Fatalf("Failed to set PORT: %v", err)
	}
	if err := os.Setenv("DB_PATH", "/custom/path.db"); err != nil {
		t.Fatalf("Failed to set DB_PATH: %v", err)
	}
	if err := os.Setenv("DEBUG_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set DEBUG_ENABLED: %v", err)
	}

	defer func() {
		// Restore original env vars
		_ = os.Setenv("PORT", origPort)
		_ = os.Setenv("DB_PATH", origDB)
		_ = os.Setenv("DEBUG_ENABLED", origDebug)
	}()

	// Load config (will not find default files, uses env vars)
	cfg, err := LoadConfigWithDefaults()
	if err != nil {
		t.Fatalf("Failed to load config with defaults: %v", err)
	}

	// Verify env vars are applied
	if cfg.Port != "5555" {
		t.Errorf("Expected port from env, got %s", cfg.Port)
	}

	if cfg.DBPath != "/custom/path.db" {
		t.Errorf("Expected db path from env, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled from env")
	}
}

func TestOTELDirectExportDefaults(t *testing.T) {
	cfg := defaultConfig()

	// Verify OTEL direct export defaults
	if !cfg.OTELUseDirectExport {
		t.Error("Expected OTELUseDirectExport to be true by default")
	}

	if cfg.OTELDirectBatchSize != 5000 {
		t.Errorf("Expected OTELDirectBatchSize to be 5000, got %d", cfg.OTELDirectBatchSize)
	}
}

func TestOTELDirectExportFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	configContent := `otel_use_direct_export=false
otel_direct_batch_size=10000
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.OTELUseDirectExport {
		t.Error("Expected OTELUseDirectExport to be false from config file")
	}

	if cfg.OTELDirectBatchSize != 10000 {
		t.Errorf("Expected OTELDirectBatchSize to be 10000, got %d", cfg.OTELDirectBatchSize)
	}
}

func TestOTELDirectExportEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	// Config file has one set of values
	configContent := `otel_use_direct_export=true
otel_direct_batch_size=5000
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set environment variables to override
	origUseDirectExport := os.Getenv("OTEL_USE_DIRECT_EXPORT")
	origDirectBatchSize := os.Getenv("OTEL_DIRECT_BATCH_SIZE")

	if err := os.Setenv("OTEL_USE_DIRECT_EXPORT", "false"); err != nil {
		t.Fatalf("Failed to set env var: %v", err)
	}
	if err := os.Setenv("OTEL_DIRECT_BATCH_SIZE", "2500"); err != nil {
		t.Fatalf("Failed to set env var: %v", err)
	}

	defer func() {
		_ = os.Setenv("OTEL_USE_DIRECT_EXPORT", origUseDirectExport)
		_ = os.Setenv("OTEL_DIRECT_BATCH_SIZE", origDirectBatchSize)
	}()

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Env vars should override file values
	if cfg.OTELUseDirectExport {
		t.Error("Expected OTELUseDirectExport to be false from env var")
	}

	if cfg.OTELDirectBatchSize != 2500 {
		t.Errorf("Expected OTELDirectBatchSize to be 2500 from env var, got %d", cfg.OTELDirectBatchSize)
	}
}

func TestOTELDirectBatchSizeValidation(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expectedValue int // Expected value (default if invalid)
	}{
		{"valid positive", "3000", 3000},
		{"zero", "0", 5000},           // Invalid, should keep default
		{"negative", "-100", 5000},    // Invalid, should keep default
		{"non-numeric", "abc", 5000},  // Invalid, should keep default
		{"empty", "", 5000},           // Invalid, should keep default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origVal := os.Getenv("OTEL_DIRECT_BATCH_SIZE")
			if err := os.Setenv("OTEL_DIRECT_BATCH_SIZE", tt.value); err != nil {
				t.Fatalf("Failed to set env var: %v", err)
			}
			defer func() {
				_ = os.Setenv("OTEL_DIRECT_BATCH_SIZE", origVal)
			}()

			cfg, err := LoadConfig("")
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if cfg.OTELDirectBatchSize != tt.expectedValue {
				t.Errorf("For value %q, expected batch size %d, got %d",
					tt.value, tt.expectedValue, cfg.OTELDirectBatchSize)
			}
		})
	}
}

func TestOTELUseDirectExportVariations(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"false lowercase", "false", false},
		{"FALSE uppercase", "FALSE", false},
		{"0", "0", false},
		{"no", "no", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test.conf")

			configContent := "otel_use_direct_export=" + tt.value + "\n"
			err := os.WriteFile(configPath, []byte(configContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if cfg.OTELUseDirectExport != tt.expected {
				t.Errorf("For value %q, expected %v, got %v",
					tt.value, tt.expected, cfg.OTELUseDirectExport)
			}
		})
	}
}
