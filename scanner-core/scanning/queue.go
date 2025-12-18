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

// JobQueue manages an unbounded queue of scan jobs and processes them serially with a single worker
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
}

// NewJobQueue creates a new job queue with the specified SBOM retriever
// Vulnerability scanning is handled internally using Grype with custom configuration
func NewJobQueue(db *database.DB, sbomRetriever SBOMRetriever, grypeCfg grype.Config) *JobQueue {
	ctx, cancel := context.WithCancel(context.Background())

	queue := &JobQueue{
		jobs:          make([]ScanJob, 0),
		sbomRetriever: sbomRetriever,
		db:            db,
		ctx:           ctx,
		cancel:        cancel,
		grypeCfg:      grypeCfg,
	}
	queue.jobsAvailable = sync.NewCond(&queue.jobsMu)

	// Start the worker goroutine
	queue.wg.Add(1)
	go queue.worker()

	log.Println("Scan job queue initialized with unbounded queue and single worker")
	return queue
}

// NewJobQueueWithDefaults creates a new job queue with default Grype configuration
// This is a convenience method for applications that don't need custom Grype settings
func NewJobQueueWithDefaults(db *database.DB, sbomRetriever SBOMRetriever) *JobQueue {
	return NewJobQueue(db, sbomRetriever, grype.Config{})
}

// Enqueue adds a scan job to the unbounded queue
// Never blocks or drops jobs
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

	q.jobs = append(q.jobs, job)
	log.Printf("Enqueued scan job: image=%s:%s (digest=%s), node=%s, runtime=%s (queue depth: %d)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest, job.NodeName, job.ContainerRuntime, len(q.jobs))

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

// GetQueueDepth returns the current number of jobs in the queue.
// This is useful for monitoring and debug purposes.
func (q *JobQueue) GetQueueDepth() int {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()
	return len(q.jobs)
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

		q.jobsMu.Unlock()

		// Process the job outside the lock
		q.processJob(job)
	}
}

// processJob handles a single scan job
func (q *JobQueue) processJob(job ScanJob) {
	log.Printf("Processing scan job: image=%s:%s (digest=%s)",
		job.Image.Repository, job.Image.Tag, job.Image.Digest)

	// Check if we already have scan results (unless force scan is requested)
	if !job.ForceScan {
		scanStatus, err := q.db.GetImageScanStatus(job.Image.Digest)
		if err != nil {
			log.Printf("Error checking scan status for %s: %v", job.Image.Digest, err)
		} else if scanStatus == "scanned" {
			log.Printf("Image %s already scanned, skipping", job.Image.Digest)
			return
		}
	}

	// Mark image as scanning
	if err := q.db.UpdateScanStatus(job.Image.Digest, "scanning", ""); err != nil {
		log.Printf("Error updating scan status for %s: %v", job.Image.Digest, err)
		return
	}

	// Call the SBOM retriever callback
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	sbomJSON, err := q.sbomRetriever(ctx, job.Image, job.NodeName, job.ContainerRuntime)
	if err != nil {
		log.Printf("Error retrieving SBOM for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		// Mark as failed
		if updateErr := q.db.UpdateScanStatus(job.Image.Digest, "failed", err.Error()); updateErr != nil {
			log.Printf("Error updating scan status to failed: %v", updateErr)
		}
		return
	}

	// Store the SBOM
	if err := q.db.StoreSBOM(job.Image.Digest, sbomJSON); err != nil {
		log.Printf("Error storing SBOM for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		// Mark as failed
		if updateErr := q.db.UpdateScanStatus(job.Image.Digest, "failed", err.Error()); updateErr != nil {
			log.Printf("Error updating scan status to failed: %v", updateErr)
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
		vulnStatus, err := q.db.GetImageVulnerabilityStatus(job.Image.Digest)
		if err != nil {
			log.Printf("Error checking vulnerability status for %s: %v", job.Image.Digest, err)
		} else if vulnStatus == "scanned" {
			log.Printf("Image %s already scanned for vulnerabilities, skipping", job.Image.Digest)
			return
		}
	}

	// Mark image as scanning for vulnerabilities
	if err := q.db.UpdateVulnerabilityStatus(job.Image.Digest, "scanning", ""); err != nil {
		log.Printf("Error updating vulnerability status for %s: %v", job.Image.Digest, err)
		return
	}

	// Scan for vulnerabilities using Grype
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	vulnJSON, err := grype.ScanVulnerabilitiesWithConfig(ctx, sbomJSON, q.grypeCfg)
	if err != nil {
		log.Printf("Error scanning vulnerabilities for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		// Mark as failed
		if updateErr := q.db.UpdateVulnerabilityStatus(job.Image.Digest, "failed", err.Error()); updateErr != nil {
			log.Printf("Error updating vulnerability status to failed: %v", updateErr)
		}
		return
	}

	// Store the vulnerability report
	if err := q.db.StoreVulnerabilities(job.Image.Digest, vulnJSON); err != nil {
		log.Printf("Error storing vulnerabilities for %s:%s: %v",
			job.Image.Repository, job.Image.Tag, err)

		// Mark as failed
		if updateErr := q.db.UpdateVulnerabilityStatus(job.Image.Digest, "failed", err.Error()); updateErr != nil {
			log.Printf("Error updating vulnerability status to failed: %v", updateErr)
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
