package config

import "time"

// Config represents the update controller configuration
type Config struct {
	Enabled            bool               `yaml:"enabled"`
	VersionConstraints VersionConstraints `yaml:"versionConstraints"`
	Helm               HelmConfig         `yaml:"helm"`
	Rollback           RollbackConfig     `yaml:"rollback"`
	Verification       VerificationConfig `yaml:"verification"`
}

// VersionConstraints defines version update policies
type VersionConstraints struct {
	AutoUpdateMinor bool   `yaml:"autoUpdateMinor"`
	AutoUpdateMajor bool   `yaml:"autoUpdateMajor"`
	PinnedVersion   string `yaml:"pinnedVersion"`
	MinVersion      string `yaml:"minVersion"`
	MaxVersion      string `yaml:"maxVersion"`
}

// HelmConfig contains Helm-specific configuration
type HelmConfig struct {
	ReleaseName   string `yaml:"releaseName"`
	Namespace     string `yaml:"namespace"`
	ChartRegistry string `yaml:"chartRegistry"`
}

// RollbackConfig defines rollback behavior
type RollbackConfig struct {
	Enabled          bool          `yaml:"enabled"`
	HealthCheckDelay time.Duration `yaml:"healthCheckDelay"`
	AutoRollback     bool          `yaml:"autoRollback"`
}

// VerificationConfig defines signature verification settings
type VerificationConfig struct {
	Enabled              bool   `yaml:"enabled"`
	CosignIdentityRegexp string `yaml:"cosignIdentityRegexp"`
	CosignOIDCIssuer     string `yaml:"cosignOIDCIssuer"`
}
