package jobs

import (
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
