package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/bvboe/b2s-go/k8s-update-controller/config"
)

// Controller manages the update process
type Controller struct {
	config         *config.Config
	helmClient     *HelmClient
	registryClient *RegistryClient
	versionChecker *VersionChecker
}

// UpdateResult contains the result of an update check
type UpdateResult struct {
	CurrentVersion   string
	LatestVersion    string
	UpdateAvailable  bool
	UpdatePerformed  bool
	UpdatedToVersion string
	Reason           string
}

// New creates a new controller
func New(cfg *config.Config) (*Controller, error) {
	// Create Helm client
	helmClient, err := NewHelmClient(cfg.Helm.Namespace, cfg.Helm.ReleaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm client: %w", err)
	}

	// Create registry client
	registryClient := NewRegistryClient(cfg.Helm.ChartRegistry)

	// Create version checker
	versionChecker := NewVersionChecker(&cfg.VersionConstraints)

	return &Controller{
		config:         cfg,
		helmClient:     helmClient,
		registryClient: registryClient,
		versionChecker: versionChecker,
	}, nil
}

// CheckAndUpdate performs a single update check and applies updates if needed
func (c *Controller) CheckAndUpdate(ctx context.Context) (*UpdateResult, error) {
	result := &UpdateResult{}

	// 1. Get current release version
	fmt.Println("Step 1: Getting current release...")
	currentRelease, err := c.helmClient.GetCurrentRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to get current release: %w", err)
	}
	result.CurrentVersion = currentRelease.Chart.Metadata.Version
	fmt.Printf("Current version: %s\n", result.CurrentVersion)

	// 2. List available versions from registry
	fmt.Println("\nStep 2: Querying registry for available versions...")
	versions, err := c.registryClient.ListVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	fmt.Printf("Found %d versions in registry\n", len(versions))

	// 3. Find latest version matching constraints
	fmt.Println("\nStep 3: Evaluating version constraints...")
	latestVersion, err := c.versionChecker.FindLatestVersion(result.CurrentVersion, versions)
	if err != nil {
		return nil, fmt.Errorf("failed to find latest version: %w", err)
	}
	result.LatestVersion = latestVersion

	// 4. Check if update should be performed
	shouldUpdate, reason := c.versionChecker.ShouldUpdate(result.CurrentVersion, latestVersion)
	fmt.Printf("Should update: %v (%s)\n", shouldUpdate, reason)

	if !shouldUpdate {
		result.UpdateAvailable = false
		result.Reason = reason
		return result, nil
	}

	result.UpdateAvailable = true

	// 5. Download chart
	fmt.Printf("\nStep 4: Downloading chart version %s...\n", latestVersion)
	chartPath, err := c.registryClient.DownloadChart(ctx, latestVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to download chart: %w", err)
	}
	defer func() {
		// Clean up downloaded chart (parent directory)
		// chartPath is like /tmp/helm-chart-12345/chart.tgz
		// We want to remove /tmp/helm-chart-12345
		if chartPath != "" {
			dir := chartPath[:len(chartPath)-len("/chart.tgz")]
			_ = c.cleanupTempDir(dir)
		}
	}()
	fmt.Printf("Chart downloaded to: %s\n", chartPath)

	// 6. Verify signature (if enabled)
	if c.config.Verification.Enabled {
		fmt.Println("\nStep 5: Verifying chart signature...")
		if err := c.registryClient.VerifySignature(ctx, chartPath,
			c.config.Verification.CosignIdentityRegexp,
			c.config.Verification.CosignOIDCIssuer); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
		fmt.Println("Signature verified ✓")
	}

	// 7. Perform Helm upgrade
	fmt.Printf("\nStep 6: Upgrading release to version %s...\n", latestVersion)
	if err := c.helmClient.UpgradeRelease(ctx, chartPath, latestVersion); err != nil {
		return nil, fmt.Errorf("helm upgrade failed: %w", err)
	}
	fmt.Println("Upgrade completed ✓")

	result.UpdatePerformed = true
	result.UpdatedToVersion = latestVersion

	// 8. Wait for health check
	if c.config.Rollback.Enabled {
		fmt.Printf("\nStep 7: Waiting %v for health check...\n", c.config.Rollback.HealthCheckDelay())
		time.Sleep(c.config.Rollback.HealthCheckDelay())

		healthy, err := c.helmClient.IsReleaseHealthy()
		if err != nil || !healthy {
			fmt.Printf("Health check failed: %v\n", err)

			if c.config.Rollback.AutoRollback {
				fmt.Println("Performing automatic rollback...")
				if rbErr := c.helmClient.RollbackRelease(); rbErr != nil {
					return nil, fmt.Errorf("rollback failed after upgrade failure: %w", rbErr)
				}
				return nil, fmt.Errorf("upgrade rolled back due to health check failure")
			}

			return nil, fmt.Errorf("health check failed but auto-rollback is disabled")
		}

		fmt.Println("Health check passed ✓")
	}

	return result, nil
}

// cleanupTempDir removes a temporary directory
func (c *Controller) cleanupTempDir(dir string) error {
	// Implementation for cleanup
	return nil
}
