package jobs

import (
	"context"
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/logging"
)

// RefreshImagesJob triggers a refresh of all running container images
// This job calls the RefreshTrigger to get updated container instance data
// and performs periodic reconciliation to catch any missed container events
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
	logging.For(logging.ComponentJobs).Info("starting periodic reconciliation of running containers")

	// Trigger the refresh - this will call back to agent/k8s-scan-server
	// which will gather running container data and call SetContainers
	err := j.refreshTrigger.TriggerRefresh()
	if err != nil {
		return fmt.Errorf("failed to trigger refresh: %w", err)
	}

	logging.For(logging.ComponentJobs).Info("reconciliation completed successfully")
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
	logging.For(logging.ComponentJobs).Info("starting cleanup of orphaned container images")

	stats, err := j.db.CleanupOrphanedImages()
	if err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}

	if stats != nil && stats.ImagesRemoved > 0 {
		logging.For(logging.ComponentJobs).Info("cleanup completed",
			"images_removed", stats.ImagesRemoved,
			"packages_removed", stats.PackagesRemoved,
			"vulnerabilities_removed", stats.VulnerabilitiesRemoved)
	} else {
		logging.For(logging.ComponentJobs).Info("cleanup completed: no orphaned images found")
	}

	return nil
}
