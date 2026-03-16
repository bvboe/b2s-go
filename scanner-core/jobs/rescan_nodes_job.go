package jobs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// NodeDatabaseInterface defines the interface for database operations needed by node rescan
type NodeDatabaseInterface interface {
	GetAllNodes() ([]nodes.NodeWithStatus, error)
	GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error)
}

// NodeScanQueueInterface defines the interface for enqueueing node scans
type NodeScanQueueInterface interface {
	EnqueueHostForceScan(nodeName string)
}

// NodeFullRescanQueueInterface defines the interface for enqueueing full node rescans
// Full rescans regenerate both the SBOM and vulnerability scan (detects package changes)
type NodeFullRescanQueueInterface interface {
	EnqueueHostFullRescan(nodeName string)
}

// RescanNodesJob periodically rescans all nodes with fresh SBOMs
// Unlike the grype DB update rescan (which reuses existing SBOMs), this job
// always retrieves a fresh SBOM because node packages can change over time.
type RescanNodesJob struct {
	db        NodeDatabaseInterface
	scanQueue NodeFullRescanQueueInterface
}

// NewRescanNodesJob creates a new rescan-nodes job
func NewRescanNodesJob(db NodeDatabaseInterface, scanQueue NodeFullRescanQueueInterface) *RescanNodesJob {
	if db == nil {
		panic("RescanNodesJob requires a non-nil database")
	}
	if scanQueue == nil {
		panic("RescanNodesJob requires a non-nil scan queue")
	}
	return &RescanNodesJob{
		db:        db,
		scanQueue: scanQueue,
	}
}

// Name returns the job name for scheduler registration
func (j *RescanNodesJob) Name() string {
	return "rescan-nodes"
}

// Run executes the rescan-nodes job
// It retrieves all completed nodes and enqueues a full rescan (fresh SBOM + vuln scan) for each
func (j *RescanNodesJob) Run(ctx context.Context) error {
	log.Printf("[rescan-nodes] Starting periodic node rescan with fresh SBOMs...")

	// Get all nodes (regardless of when they were last scanned)
	nodeList, err := j.db.GetAllNodes()
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	if len(nodeList) == 0 {
		log.Printf("[rescan-nodes] No nodes found, nothing to rescan")
		return nil
	}

	// Filter to only completed nodes (have been scanned at least once)
	var completedNodes []nodes.NodeWithStatus
	for _, node := range nodeList {
		if node.Status == "completed" || node.Status == "scanned" {
			completedNodes = append(completedNodes, node)
		}
	}

	if len(completedNodes) == 0 {
		log.Printf("[rescan-nodes] No completed nodes found, nothing to rescan")
		return nil
	}

	log.Printf("[rescan-nodes] Found %d completed nodes, triggering full rescan with fresh SBOMs", len(completedNodes))

	// Enqueue full rescan for each node
	// FullRescan=true forces fresh SBOM retrieval (node packages may have changed)
	for _, node := range completedNodes {
		j.scanQueue.EnqueueHostFullRescan(node.Name)
	}

	log.Printf("[rescan-nodes] Enqueued %d nodes for full rescan", len(completedNodes))
	return nil
}

// RescanNodesOnDBUpdate rescans nodes that were scanned with an older grype database
// This is called by the existing RescanDatabaseJob when the grype DB updates,
// rather than running as a separate scheduled job. This avoids unnecessary
// duplicate rescans since the grype DB typically updates every 24 hours.
func RescanNodesOnDBUpdate(db NodeDatabaseInterface, scanQueue NodeScanQueueInterface, currentGrypeDBBuilt time.Time) error {
	if db == nil || scanQueue == nil {
		return nil // Host scanning not configured
	}

	log.Printf("[rescan-nodes] Checking nodes for vulnerability database update...")

	// Find nodes that were scanned with an older grype database
	nodeList, err := db.GetNodesNeedingRescan(currentGrypeDBBuilt)
	if err != nil {
		return fmt.Errorf("failed to get nodes needing rescan: %w", err)
	}

	if len(nodeList) == 0 {
		log.Printf("[rescan-nodes] All nodes are up-to-date with current grype DB, nothing to rescan")
		return nil
	}

	log.Printf("[rescan-nodes] Found %d nodes scanned with older grype DB, triggering rescan", len(nodeList))

	// Enqueue force scan for each node
	// ForceScan=true skips SBOM regeneration (uses existing SBOM), only reruns vulnerability scan
	for _, node := range nodeList {
		scanQueue.EnqueueHostForceScan(node.Name)
	}

	log.Printf("[rescan-nodes] Enqueued %d nodes for rescanning", len(nodeList))
	return nil
}
