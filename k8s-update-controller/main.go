package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bvboe/b2s-go/k8s-update-controller/config"
	"github.com/bvboe/b2s-go/k8s-update-controller/controller"
)

var version = "dev" // Set via ldflags at build time

func main() {
	ctx := context.Background()

	fmt.Printf("Bjorn2Scan Update Controller %s\n", version)
	fmt.Println("Starting update check...")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	if !cfg.Enabled {
		fmt.Println("Auto-update is disabled in configuration")
		os.Exit(0)
	}

	fmt.Printf("Configuration loaded:\n")
	fmt.Printf("  Release: %s/%s\n", cfg.Helm.Namespace, cfg.Helm.ReleaseName)
	fmt.Printf("  Chart Registry: %s\n", cfg.Helm.ChartRegistry)
	fmt.Printf("  Auto-update minor: %v\n", cfg.VersionConstraints.AutoUpdateMinor)
	fmt.Printf("  Auto-update major: %v\n", cfg.VersionConstraints.AutoUpdateMajor)
	if cfg.VersionConstraints.PinnedVersion != "" {
		fmt.Printf("  Pinned version: %s\n", cfg.VersionConstraints.PinnedVersion)
	}

	// Create controller
	ctrl, err := controller.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating controller: %v\n", err)
		os.Exit(1)
	}

	// Run update check (one-shot execution)
	startTime := time.Now()
	result, err := ctrl.CheckAndUpdate(ctx)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during update check: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("\nUpdate check completed in %v\n", duration.Round(time.Second))
	fmt.Printf("Current version: %s\n", result.CurrentVersion)
	fmt.Printf("Latest available: %s\n", result.LatestVersion)

	if result.UpdatePerformed {
		fmt.Printf("✓ Update performed: %s → %s\n", result.CurrentVersion, result.UpdatedToVersion)
		fmt.Println("Next scheduled run will use the new version!")
	} else if result.UpdateAvailable {
		fmt.Printf("Update available but not applied: %s\n", result.Reason)
	} else {
		fmt.Println("System is up to date")
	}

	os.Exit(0)
}
