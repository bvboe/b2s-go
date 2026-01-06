package jobs

import (
	"context"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
)

// RefreshImagesJob triggers a refresh of all running container images
// This job calls the RefreshTrigger to get updated container instance data
type RefreshImagesJob struct {
	refreshTrigger containers.RefreshTrigger
}

// NewRefreshImagesJob creates a new refresh images job
func NewRefreshImagesJob(trigger containers.RefreshTrigger) *RefreshImagesJob {
	if trigger == nil {
		panic("RefreshImagesJob requires a non-nil RefreshTrigger")
	}
	return &RefreshImagesJob{
		refreshTrigger: trigger,
	}
}

func (j *RefreshImagesJob) Name() string {
	return "refresh-images"
}

func (j *RefreshImagesJob) Run(ctx context.Context) error {
	log.Printf("[refresh-images] Starting periodic reconciliation of running containers")

	// Trigger the refresh - this will call back to agent/k8s-scan-server
	// which will gather running container data and call SetContainerInstances
	err := j.refreshTrigger.TriggerRefresh()
	if err != nil {
		return fmt.Errorf("failed to trigger refresh: %w", err)
	}

	log.Printf("[refresh-images] Reconciliation triggered successfully")
	return nil
}

// CleanupOrphanedImagesJob deletes container images that have no associated container instances
// This also removes related packages and vulnerabilities to keep the database clean
type CleanupOrphanedImagesJob struct {
	db DatabaseCleanup
}

// DatabaseCleanup defines the interface for database cleanup operations
type DatabaseCleanup interface {
	CleanupOrphanedImages() (*database.CleanupStats, error)
}

// NewCleanupOrphanedImagesJob creates a new cleanup job
func NewCleanupOrphanedImagesJob(db DatabaseCleanup) *CleanupOrphanedImagesJob {
	if db == nil {
		panic("CleanupOrphanedImagesJob requires a non-nil database")
	}
	return &CleanupOrphanedImagesJob{
		db: db,
	}
}

func (j *CleanupOrphanedImagesJob) Name() string {
	return "cleanup-orphaned-images"
}

func (j *CleanupOrphanedImagesJob) Run(ctx context.Context) error {
	log.Printf("[cleanup] Starting cleanup of orphaned container images")

	stats, err := j.db.CleanupOrphanedImages()
	if err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}

	if stats != nil && stats.ImagesRemoved > 0 {
		log.Printf("[cleanup] Cleanup completed: removed %d images, %d packages, %d vulnerabilities",
			stats.ImagesRemoved, stats.PackagesRemoved, stats.VulnerabilitiesRemoved)
	} else {
		log.Printf("[cleanup] Cleanup completed: no orphaned images found")
	}

	return nil
}

// TelemetryJob sends metrics and data to OpenTelemetry collector
type TelemetryJob struct {
	// Add OpenTelemetry client dependency
}

func NewTelemetryJob() *TelemetryJob {
	return &TelemetryJob{}
}

func (j *TelemetryJob) Name() string {
	return "telemetry"
}

func (j *TelemetryJob) Run(ctx context.Context) error {
	// TODO: Implement logic to:
	// 1. Collect metrics/data
	// 2. Send to OpenTelemetry collector
	log.Printf("[telemetry] Job execution - implementation pending")
	return nil
}
