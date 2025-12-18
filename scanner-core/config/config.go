// Package config provides configuration loading for bjorn2scan components.
// It supports loading from properties/INI files with environment variable overrides.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/ini.v1"
)

// Config holds all configuration options for bjorn2scan components.
type Config struct {
	Port         string
	DBPath       string
	DebugEnabled bool
	// Future: LogLevel, CacheSize, Timeouts, etc.
}

// defaultConfig returns a Config with hardcoded defaults.
func defaultConfig() *Config {
	return &Config{
		Port:         "9999",
		DBPath:       "/var/lib/bjorn2scan/containers.db",
		DebugEnabled: false,
	}
}

// LoadConfig loads configuration from the specified file path.
// Environment variables override file values.
// Precedence: environment variables > config file > defaults
func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	// Try to load config file
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			iniFile, err := ini.Load(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
			}

			section := iniFile.Section("")

			// Load port
			if section.HasKey("port") {
				cfg.Port = section.Key("port").String()
			}

			// Load database path
			if section.HasKey("db_path") {
				cfg.DBPath = section.Key("db_path").String()
			}

			// Load debug enabled
			if section.HasKey("debug_enabled") {
				debugStr := strings.ToLower(section.Key("debug_enabled").String())
				cfg.DebugEnabled = debugStr == "true" || debugStr == "1" || debugStr == "yes"
			}
		} else if !os.IsNotExist(err) {
			// File exists but can't be read
			return nil, fmt.Errorf("cannot access config file %s: %w", path, err)
		}
		// If file doesn't exist, just use defaults (no error)
	}

	// Override with environment variables
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		cfg.Port = portEnv
	}

	if dbPathEnv := os.Getenv("DB_PATH"); dbPathEnv != "" {
		cfg.DBPath = dbPathEnv
	}

	if debugEnv := os.Getenv("DEBUG_ENABLED"); debugEnv != "" {
		debugStr := strings.ToLower(debugEnv)
		cfg.DebugEnabled = debugStr == "true" || debugStr == "1" || debugStr == "yes"
	}

	return cfg, nil
}

// LoadConfigWithDefaults tries to load configuration from default locations.
// It checks locations in order:
// 1. /etc/bjorn2scan/agent.conf
// 2. ./agent.conf (current directory)
// 3. Hardcoded defaults
//
// Environment variables override file values.
func LoadConfigWithDefaults() (*Config, error) {
	// Check default locations in order
	defaultPaths := []string{
		"/etc/bjorn2scan/agent.conf",
		"./agent.conf",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			// File exists, try to load it
			cfg, err := LoadConfig(path)
			if err != nil {
				// File exists but failed to parse - return error
				return nil, err
			}
			return cfg, nil
		}
	}

	// No config file found, use defaults with env var overrides
	return LoadConfig("")
}
