// Package config provides configuration loading for bjorn2scan components.
// It supports loading from properties/INI files with environment variable overrides.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// Config holds all configuration options for bjorn2scan components.
type Config struct {
	Port         string
	DBPath       string
	DebugEnabled bool

	// Auto-update configuration
	AutoUpdateEnabled          bool
	AutoUpdateCheckInterval    time.Duration
	AutoUpdateMinorVersions    bool
	AutoUpdateMajorVersions    bool
	AutoUpdatePinnedVersion    string
	AutoUpdateMinVersion       string
	AutoUpdateMaxVersion       string
	UpdateFeedURL              string
	UpdateAssetBaseURL         string
	UpdateVerifySignatures     bool
	UpdateRollbackEnabled      bool
	UpdateHealthCheckTimeout   time.Duration
	UpdateCosignIdentityRegexp string
	UpdateCosignOIDCIssuer     string
}

// defaultConfig returns a Config with hardcoded defaults.
func defaultConfig() *Config {
	return &Config{
		Port:         "9999",
		DBPath:       "/var/lib/bjorn2scan/data/containers.db",
		DebugEnabled: false,

		// Auto-update defaults
		AutoUpdateEnabled:          true,
		//Todo - revert back to something more reasonable
		AutoUpdateCheckInterval:    1 * time.Hour,
		AutoUpdateMinorVersions:    true,
		AutoUpdateMajorVersions:    false,
		AutoUpdatePinnedVersion:    "",
		AutoUpdateMinVersion:       "",
		AutoUpdateMaxVersion:       "",
		UpdateFeedURL:              "https://github.com/bvboe/b2s-go/releases.atom",
		UpdateAssetBaseURL:         "https://github.com/bvboe/b2s-go/releases/download",
		UpdateVerifySignatures:     false, // TODO: Enable when cosign is implemented
		UpdateRollbackEnabled:      true,
		UpdateHealthCheckTimeout:   60 * time.Second,
		UpdateCosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*",
		UpdateCosignOIDCIssuer:     "https://token.actions.githubusercontent.com",
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

			// Load auto-update settings
			if section.HasKey("auto_update_enabled") {
				val := strings.ToLower(section.Key("auto_update_enabled").String())
				cfg.AutoUpdateEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_check_interval") {
				if duration, err := time.ParseDuration(section.Key("auto_update_check_interval").String()); err == nil {
					cfg.AutoUpdateCheckInterval = duration
				}
			}
			if section.HasKey("auto_update_minor_versions") {
				val := strings.ToLower(section.Key("auto_update_minor_versions").String())
				cfg.AutoUpdateMinorVersions = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_major_versions") {
				val := strings.ToLower(section.Key("auto_update_major_versions").String())
				cfg.AutoUpdateMajorVersions = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_pinned_version") {
				cfg.AutoUpdatePinnedVersion = section.Key("auto_update_pinned_version").String()
			}
			if section.HasKey("auto_update_min_version") {
				cfg.AutoUpdateMinVersion = section.Key("auto_update_min_version").String()
			}
			if section.HasKey("auto_update_max_version") {
				cfg.AutoUpdateMaxVersion = section.Key("auto_update_max_version").String()
			}
			if section.HasKey("update_feed_url") {
				cfg.UpdateFeedURL = section.Key("update_feed_url").String()
			}
			if section.HasKey("update_asset_base_url") {
				cfg.UpdateAssetBaseURL = section.Key("update_asset_base_url").String()
			}
			if section.HasKey("update_verify_signatures") {
				val := strings.ToLower(section.Key("update_verify_signatures").String())
				cfg.UpdateVerifySignatures = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("update_rollback_enabled") {
				val := strings.ToLower(section.Key("update_rollback_enabled").String())
				cfg.UpdateRollbackEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("update_health_check_timeout") {
				if duration, err := time.ParseDuration(section.Key("update_health_check_timeout").String()); err == nil {
					cfg.UpdateHealthCheckTimeout = duration
				} else if seconds, err := strconv.Atoi(section.Key("update_health_check_timeout").String()); err == nil {
					cfg.UpdateHealthCheckTimeout = time.Duration(seconds) * time.Second
				}
			}
			if section.HasKey("update_cosign_identity_regexp") {
				cfg.UpdateCosignIdentityRegexp = section.Key("update_cosign_identity_regexp").String()
			}
			if section.HasKey("update_cosign_oidc_issuer") {
				cfg.UpdateCosignOIDCIssuer = section.Key("update_cosign_oidc_issuer").String()
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
