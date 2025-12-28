package jobs

import (
	"context"
	"fmt"
	"log"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
)

// FeedCheckerInterface defines the interface for checking vulnerability database updates
type FeedCheckerInterface interface {
	CheckForUpdates(ctx context.Context) (bool, error)
}

// DatabaseInterface defines the interface for database operations needed by RescanDatabaseJob
type DatabaseInterface interface {
	GetImagesByStatus(status database.Status) ([]database.ContainerImage, error)
	GetFirstInstanceForImage(digest string) (*database.ContainerInstanceRow, error)
}

// RescanDatabaseJob triggers a rescan when the vulnerability database is updated
type RescanDatabaseJob struct {
	feedChecker FeedCheckerInterface
	db          DatabaseInterface
	scanQueue   ScanQueueInterface
}

// NewRescanDatabaseJob creates a new rescan database job
func NewRescanDatabaseJob(feedChecker FeedCheckerInterface, db DatabaseInterface, scanQueue ScanQueueInterface) *RescanDatabaseJob {
	if feedChecker == nil {
		panic("RescanDatabaseJob requires a non-nil FeedChecker")
	}
	if db == nil {
		panic("RescanDatabaseJob requires a non-nil database")
	}
	if scanQueue == nil {
		panic("RescanDatabaseJob requires a non-nil scan queue")
	}

	return &RescanDatabaseJob{
		feedChecker: feedChecker,
		db:          db,
		scanQueue:   scanQueue,
	}
}

func (j *RescanDatabaseJob) Name() string {
	return "rescan-database"
}

func (j *RescanDatabaseJob) Run(ctx context.Context) error {
	log.Printf("[rescan-database] Checking for vulnerability database updates...")

	// Check if database has been updated
	hasChanged, err := j.feedChecker.CheckForUpdates(ctx)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if !hasChanged {
		log.Printf("[rescan-database] No database changes detected, skipping rescan")
		return nil
	}

	log.Printf("[rescan-database] Database update detected, triggering rescan of all images")

	// Get all completed images (those that have SBOMs)
	images, err := j.db.GetImagesByStatus(database.StatusCompleted)
	if err != nil {
		return fmt.Errorf("failed to get completed images: %w", err)
	}

	if len(images) == 0 {
		log.Printf("[rescan-database] No completed images found, nothing to rescan")
		return nil
	}

	log.Printf("[rescan-database] Found %d images to rescan", len(images))

	// Enqueue force scan for each image
	rescanned := 0
	for _, img := range images {
		// Get the first instance to determine node and runtime
		instance, err := j.db.GetFirstInstanceForImage(img.Digest)
		if err != nil {
			log.Printf("[rescan-database] Warning: could not find instance for image %s: %v", img.Digest, err)
			continue
		}

		// Enqueue force scan (ForceScan=true skips SBOM generation, only runs Grype)
		j.scanQueue.EnqueueForceScan(
			containers.ImageID{
				Digest:     img.Digest,
				Repository: instance.Repository,
				Tag:        instance.Tag,
			},
			instance.NodeName,
			instance.ContainerRuntime,
		)
		rescanned++
	}

	log.Printf("[rescan-database] Enqueued %d images for rescanning", rescanned)
	return nil
}

// ScanQueueInterface defines the interface for enqueueing scans
type ScanQueueInterface interface {
	EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string)
}

// Ensure scanning.JobQueue implements ScanQueueInterface
var _ ScanQueueInterface = (*scanning.JobQueue)(nil)

// Ensure database.DB implements DatabaseInterface
var _ DatabaseInterface = (*database.DB)(nil)

// Ensure vulndb.FeedChecker implements FeedCheckerInterface
var _ FeedCheckerInterface = (*vulndb.FeedChecker)(nil)
