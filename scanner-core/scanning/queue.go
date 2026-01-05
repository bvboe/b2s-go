package scanning

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
)

// ScanJob represents a request to scan a container image
type ScanJob struct {
	Image            containers.ImageID
	NodeName         string // K8s node name where image is located (empty for agent)
	ContainerRuntime string // "docker" or "containerd"
	ForceScan        bool   // If true, rescan even if SBOM already exists
}

// SBOMRetriever is a callback function that retrieves an SBOM for an image
// The implementation is provided by the caller (agent or k8s-scan-server)
// Returns the SBOM as JSON bytes, or an error
type SBOMRetriever func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error)

// QueueFullBehavior defines what happens when the queue reaches max depth
type QueueFullBehavior int

const (
	// QueueFullDrop drops the new job and logs a warning (default)
	QueueFullDrop QueueFullBehavior = iota
	// QueueFullDropOldest removes the oldest job and adds the new one
	QueueFullDropOldest
	// QueueFullBlock blocks until space is available (may cause goroutine buildup)
	QueueFullBlock
)

// QueueConfig configures the job queue behavior
type QueueConfig struct {
	// MaxDepth is the maximum number of jobs in the queue (0 = unbounded)
	MaxDepth int
	// FullBehavior defines what happens when queue is full
	FullBehavior QueueFullBehavior
}

// QueueMetrics tracks queue statistics
type QueueMetrics struct {
	currentDepth   int
	peakDepth      int
	totalEnqueued  int64
	totalDropped   int64
	totalProcessed int64
	mu             sync.RWMutex
}

// JobQueue manages a queue of scan jobs and processes them serially with a single worker
type JobQueue struct {
	jobs          []ScanJob
	jobsMu        sync.Mutex
	jobsAvailable *sync.Cond
	sbomRetriever SBOMRetriever
	db            *database.DB
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	grypeCfg      grype.Config
	config        QueueConfig
	metrics       QueueMetrics
}

// NewJobQueue creates a new job queue with the specified SBOM retriever and configuration
// Vulnerability scanning is handled internally using Grype with custom configuration
func NewJobQueue(db *database.DB, sbomRetriever SBOMRetriever, grypeCfg grype.Config, queueCfg QueueConfig) *JobQueue {
	ctx, cancel := context.WithCancel(context.Background())

	queue := &JobQueue{
		jobs:          make([]ScanJob, 0),
		sbomRetriever: sbomRetriever,
		db:            db,
		ctx:           ctx,
		cancel:        cancel,
		grypeCfg:      grypeCfg,
		config:        queueCfg,
	}
	queue.jobsAvailable = sync.NewCond(&queue.jobsMu)

	// Start the worker goroutine
	queue.wg.Add(1)
	go queue.worker()

	if queueCfg.MaxDepth > 0 {
		log.Printf("Scan job queue initialized with max depth %d, behavior: %v", queueCfg.MaxDepth, queueCfg.FullBehavior)
	} else {
		log.Println("Scan job queue initialized with unbounded queue and single worker")
	}
	return queue
}

// NewJobQueueWithDefaults creates a new job queue with default Grype and queue configuration
// This is a convenience method for applications that don't need custom settings
// Default: unbounded queue (MaxDepth=0), drops new jobs when full (though it never fills)
func NewJobQueueWithDefaults(db *database.DB, sbomRetriever SBOMRetriever) *JobQueue {
	return NewJobQueue(db, sbomRetriever, grype.Config{}, QueueConfig{MaxDepth: 0, FullBehavior: QueueFullDrop})
}

// Enqueue adds a scan job to the queue with respect to max depth and full behavior
func (q *JobQueue) Enqueue(job ScanJob) {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()

	// Check if shutting down
	select {
	case <-q.ctx.Done():
		log.Println("Queue shutting down, cannot enqueue job")
		return
	default:
	}

	// Check if queue is at max depth
	if q.config.MaxDepth > 0 && len(q.jobs) >= q.config.MaxDepth {
		switch q.config.FullBehavior {
		case QueueFullDrop:
			// Drop the new job
			log.Printf("Queue full (depth=%d), dropping new job: image=%s:%s (digest=%s)",
				len(q.jobs), job.Image.Repository, job.Image.Tag, job.Image.Digest)
			q.updateMetrics(0, 0, 1) // Increment dropped count
			return

		case QueueFullDropOldest:
			// Remove oldest job and add new one
			dropped := q.jobs[0]
			q.jobs = q.jobs[1:]
			log.Printf("Queue full (depth=%d), dropping oldest job: image=%s:%s, adding new: image=%s:%s",
				len(q.jobs)+1, dropped.Image.Repository, dropped.Image.Tag,
				job.Image.Repository, job.Image.Tag)
			q.updateMetrics(0, 0, 1) // Increment dropped count

		case QueueFullBlock:
			// Block until space is available
			// Release lock and wait for signal
			for len(q.jobs) >= q.config.MaxDepth {
				q.jobsAvailable.Wait()
				// Check shutdown again after waking up
				select {
				case <-q.ctx.Done():
					log.Println("Queue shutting down while waiting to enqueue")
					return
				default:
				}
			}
		}
	}

	// Add job to queue
	q.jobs = append(q.jobs, job)
	currentDepth := len(q.jobs)

	log.Printf("Enqueued scan job: image=%s:%s (digest=%s), node=%s, runtime=%s (queue depth: %d)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest, job.NodeName, job.ContainerRuntime, currentDepth)

	// Update metrics
	q.updateMetrics(currentDepth, 1, 0)

	q.jobsAvailable.Signal()
}

// EnqueueScan is a convenience method for enqueuing a scan with individual parameters
// This implements the ScanQueueInterface used by the container manager
func (q *JobQueue) EnqueueScan(image containers.ImageID, nodeName string, containerRuntime string) {
	job := ScanJob{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
		ForceScan:        false,
	}
	q.Enqueue(job)
}

// EnqueueForceScan enqueues a scan job with ForceScan=true to retry failed or incomplete scans
// This implements the ScanQueueInterface used by the container manager
func (q *JobQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	job := ScanJob{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
		ForceScan:        true,
	}
	q.Enqueue(job)
}

// updateMetrics updates queue metrics (must be called with jobsMu held or metrics.mu)
func (q *JobQueue) updateMetrics(currentDepth int, enqueued int64, dropped int64) {
	q.metrics.mu.Lock()
	defer q.metrics.mu.Unlock()

	if currentDepth > 0 {
		q.metrics.currentDepth = currentDepth
		if currentDepth > q.metrics.peakDepth {
			q.metrics.peakDepth = currentDepth
		}
	}

	if enqueued > 0 {
		q.metrics.totalEnqueued += enqueued
	}

	if dropped > 0 {
		q.metrics.totalDropped += dropped
	}
}

// GetQueueDepth returns the current number of jobs in the queue.
// This is useful for monitoring and debug purposes.
func (q *JobQueue) GetQueueDepth() int {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()
	return len(q.jobs)
}

// GetMetrics returns a snapshot of queue metrics
func (q *JobQueue) GetMetrics() (currentDepth, peakDepth int, totalEnqueued, totalDropped, totalProcessed int64) {
	q.metrics.mu.RLock()
	defer q.metrics.mu.RUnlock()

	return q.metrics.currentDepth, q.metrics.peakDepth,
		q.metrics.totalEnqueued, q.metrics.totalDropped, q.metrics.totalProcessed
}

// worker processes jobs from the queue serially (one at a time)
func (q *JobQueue) worker() {
	defer q.wg.Done()

	log.Println("Scan worker started")

	for {
		q.jobsMu.Lock()

		// Wait for jobs to be available or shutdown signal
		for len(q.jobs) == 0 {
			select {
			case <-q.ctx.Done():
				q.jobsMu.Unlock()
				log.Println("Scan worker shutting down")
				return
			default:
			}

			// Wait for a job to be enqueued
			q.jobsAvailable.Wait()

			// Check shutdown again after waking up
			select {
			case <-q.ctx.Done():
				q.jobsMu.Unlock()
				log.Println("Scan worker shutting down")
				return
			default:
			}
		}

		// Dequeue the first job
		job := q.jobs[0]
		q.jobs = q.jobs[1:]
		currentDepth := len(q.jobs)

		// Update current depth metric
		q.updateMetrics(currentDepth, 0, 0)

		// Signal that space is available (for QueueFullBlock behavior)
		q.jobsAvailable.Signal()

		q.jobsMu.Unlock()

		// Process the job outside the lock
		q.processJob(job)

		// Update processed count
		q.metrics.mu.Lock()
		q.metrics.totalProcessed++
		q.metrics.mu.Unlock()
	}
}

// processJob handles a single scan job
func (q *JobQueue) processJob(job ScanJob) {
	log.Printf("Processing scan job: image=%s:%s (digest=%s, forceScan=%v)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest, job.ForceScan)

	// Check if we already have scan results
	status, err := q.db.GetImageStatus(job.Image.Digest)
	if err != nil {
		log.Printf("Error checking status for %s: %v", job.Image.Digest, err)
	}

	// If ForceScan is requested and SBOM already exists, skip directly to vulnerability scan
	// This is used by the rescan-database job when the grype database is updated
	if job.ForceScan && status.HasSBOM() {
		log.Printf("Force scan requested for %s with existing SBOM, running vulnerability scan only", job.Image.Digest)
		q.processVulnerabilityScan(job, nil)
		return
	}

	// Skip if SBOM already exists (unless force scan without SBOM)
	if !job.ForceScan && status.HasSBOM() {
		log.Printf("Image %s already has SBOM (status=%s), skipping SBOM generation", job.Image.Digest, status)
		// If SBOM exists but vulnerabilities don't, continue to vulnerability scan
		if !status.HasVulnerabilities() {
			q.processVulnerabilityScan(job, nil)
		}
		return
	}

	// Mark image as generating SBOM
	if err := q.db.UpdateStatus(job.Image.Digest, database.StatusGeneratingSBOM, ""); err != nil {
		log.Printf("Error updating status for %s: %v", job.Image.Digest, err)
		return
	}

	// Call the SBOM retriever callback
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	sbomJSON, err := q.sbomRetriever(ctx, job.Image, job.NodeName, job.ContainerRuntime)
	if err != nil {
		log.Printf("Error retrieving SBOM for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		// Determine if this is a failure or unavailability
		// If no node scanner is available, mark as unavailable; otherwise failed
		// For now, assume all errors are failures
		errorStatus := database.StatusSBOMFailed

		if updateErr := q.db.UpdateStatus(job.Image.Digest, errorStatus, err.Error()); updateErr != nil {
			log.Printf("Error updating status to %s: %v", errorStatus, updateErr)
		}
		return
	}

	// Store the SBOM in the database for caching (enables fast API access and offline serving)
	// Note: This is the primary SBOM caching path. Direct API requests to k8s-scan-server
	// that fetch SBOMs on-demand from pod-scanner do NOT cache (see handlers/sbom.go).
	// StoreSBOM will automatically update status to StatusScanningVulnerabilities
	if err := q.db.StoreSBOM(job.Image.Digest, sbomJSON); err != nil {
		log.Printf("Error storing SBOM for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusSBOMFailed, err.Error()); updateErr != nil {
			log.Printf("Error updating status to failed: %v", updateErr)
		}
		return
	}

	log.Printf("Successfully scanned and stored SBOM for %s:%s (digest=%s)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest)

	// Now scan for vulnerabilities
	q.processVulnerabilityScan(job, sbomJSON)
}

// processVulnerabilityScan scans an SBOM for vulnerabilities
func (q *JobQueue) processVulnerabilityScan(job ScanJob, sbomJSON []byte) {
	log.Printf("Starting vulnerability scan for %s:%s (digest=%s)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest)

	// Check if we already have vulnerability results (unless force scan is requested)
	if !job.ForceScan {
		status, err := q.db.GetImageStatus(job.Image.Digest)
		if err != nil {
			log.Printf("Error checking status for %s: %v", job.Image.Digest, err)
		} else if status.HasVulnerabilities() {
			log.Printf("Image %s already has vulnerabilities (status=%s), skipping", job.Image.Digest, status)
			return
		}
	}

	// If sbomJSON is nil, retrieve it from the database
	if sbomJSON == nil {
		var err error
		sbomJSON, err = q.db.GetSBOM(job.Image.Digest)
		if err != nil {
			log.Printf("Error retrieving SBOM from database for %s: %v", job.Image.Digest, err)
			if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, "SBOM not available: "+err.Error()); updateErr != nil {
				log.Printf("Error updating status to failed: %v", updateErr)
			}
			return
		}
	}

	// Scan for vulnerabilities using Grype
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	vulnJSON, err := grype.ScanVulnerabilitiesWithConfig(ctx, sbomJSON, q.grypeCfg)
	if err != nil {
		log.Printf("Error scanning vulnerabilities for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Printf("Error updating status to failed: %v", updateErr)
		}
		return
	}

	// Store the vulnerability report
	// StoreVulnerabilities will automatically update status to StatusCompleted
	if err := q.db.StoreVulnerabilities(job.Image.Digest, vulnJSON); err != nil {
		log.Printf("Error storing vulnerabilities for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Printf("Error updating status to failed: %v", updateErr)
		}
		return
	}

	log.Printf("Successfully scanned and stored vulnerabilities for %s:%s (digest=%s)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest)
}

// Shutdown gracefully shuts down the queue, waiting for current job to complete
func (q *JobQueue) Shutdown() {
	log.Println("Shutting down scan queue...")
	q.cancel()

	// Wake up the worker so it can see the shutdown signal
	q.jobsAvailable.Broadcast()

	q.wg.Wait()
	log.Println("Scan queue shut down")
}
