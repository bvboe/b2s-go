package nodes

import (
	"log/slog"
	"sync"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentNodes)

// NodeDatabaseInterface defines the interface for node database operations
type NodeDatabaseInterface interface {
	AddNode(n Node) (bool, error)
	UpdateNode(n Node) error
	RemoveNode(name string) error
	GetNode(name string) (*NodeWithStatus, error)
	GetAllNodes() ([]NodeWithStatus, error)
	GetNodeScanStatus(name string) (string, error)
	GetNodeScanStatusBulk(names []string) (map[string]string, error)
	IsNodeScanComplete(name string) (bool, error)
	IsNodeScanCompleteBulk(names []string) (map[string]bool, error)
}

// NodeScanQueueInterface defines the interface for enqueuing node scan jobs
type NodeScanQueueInterface interface {
	EnqueueHostScan(nodeName string)
	EnqueueHostForceScan(nodeName string)
}

// Manager handles node lifecycle management
type Manager struct {
	mu        sync.RWMutex
	nodes     map[string]Node // key: node name
	db        NodeDatabaseInterface
	scanQueue NodeScanQueueInterface
}

// NewManager creates a new node manager
func NewManager() *Manager {
	return &Manager{
		nodes: make(map[string]Node),
	}
}

// SetDatabase configures the manager to use a database for persistence
func (m *Manager) SetDatabase(db NodeDatabaseInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
	log.Info("database persistence enabled")
}

// SetScanQueue configures the manager to use a scan queue for host SBOM generation
// After setting the queue, it enqueues scans for any nodes that were discovered
// before the queue was connected (catch-up for initial sync)
func (m *Manager) SetScanQueue(queue NodeScanQueueInterface) {
	m.mu.Lock()
	m.scanQueue = queue
	log.Info("scan queue enabled")

	// Catch-up: enqueue scans for nodes discovered before queue was connected
	if m.db != nil && len(m.nodes) > 0 {
		nodeCount := len(m.nodes)
		log.Info("checking nodes for pending scans", "count", nodeCount)

		// Build map of node name -> node
		nodeMap := make(map[string]Node)
		nodeNames := make([]string, 0, nodeCount)
		for _, n := range m.nodes {
			nodeMap[n.Name] = n
			nodeNames = append(nodeNames, n.Name)
		}
		m.mu.Unlock()

		if len(nodeNames) == 0 {
			log.Debug("no nodes to check for pending scans")
			return
		}

		// Get status for all nodes in a single bulk query
		scanStatuses, err := m.db.GetNodeScanStatusBulk(nodeNames)
		if err != nil {
			log.Error("failed to fetch bulk node scan status", slog.Any("error", err))
			return
		}

		// Identify nodes that need completeness check (those marked as "completed")
		scannedNodes := make([]string, 0)
		for name, status := range scanStatuses {
			if status == "completed" {
				scannedNodes = append(scannedNodes, name)
			}
		}

		// Get completeness status for scanned nodes in a single bulk query
		var completenessStatus map[string]bool
		if len(scannedNodes) > 0 {
			completenessStatus, err = m.db.IsNodeScanCompleteBulk(scannedNodes)
			if err != nil {
				log.Error("failed to fetch bulk node completeness status", slog.Any("error", err))
				completenessStatus = make(map[string]bool)
			}
		} else {
			completenessStatus = make(map[string]bool)
		}

		// Enqueue scans based on status (using actual database status values)
		log := log
		enqueuedCount := 0
		for name, status := range scanStatuses {
			switch status {
			case "pending":
				// New node, enqueue normal scan
				log.Debug("enqueuing scan for new node", "node", name)
				m.scanQueue.EnqueueHostScan(name)
				enqueuedCount++

			case "sbom_failed", "sbom_unavailable", "vuln_scan_failed":
				// Previous scan failed, retry with force scan
				log.Debug("retrying failed scan", "node", name, "status", status)
				m.scanQueue.EnqueueHostForceScan(name)
				enqueuedCount++

			case "completed":
				// Check if data is actually complete
				if !completenessStatus[name] {
					log.Debug("retrying scan for incomplete data", "node", name)
					m.scanQueue.EnqueueHostForceScan(name)
					enqueuedCount++
				}

			case "generating_sbom", "scanning_vulnerabilities":
				// Node is in an intermediate state (previous scan was interrupted)
				log.Debug("retrying interrupted scan", "node", name)
				m.scanQueue.EnqueueHostForceScan(name)
				enqueuedCount++
			}
		}

		log.Info("queued catch-up scans", "enqueued", enqueuedCount, "total", len(nodeNames))
		return
	}
	m.mu.Unlock()
}

// AddNode adds or updates a node in the manager
func (m *Manager) AddNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[n.Name] = n

	log.Info("add node",
		"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)

	// Persist to database if configured
	if m.db != nil {
		isNew, err := m.db.AddNode(n)
		if err != nil {
			log.Error("failed to add node to database",
				"node", n.Name, slog.Any("error", err))
			return
		}

		// Only enqueue scan for NEW nodes. Existing nodes are handled by:
		// - CatchUpScans() at startup (retries failed/interrupted scans)
		// - RescanNodesOnDBUpdate() when grype DB updates
		// This avoids unnecessary retries on every K8s node event (~every 30-90s)
		if isNew && m.scanQueue != nil {
			m.scanQueue.EnqueueHostScan(n.Name)
		}
	}
}

// UpdateNode updates an existing node
func (m *Manager) UpdateNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if node exists
	_, exists := m.nodes[n.Name]
	if !exists {
		log.Debug("node not found, adding instead", "node", n.Name)
	}

	m.nodes[n.Name] = n

	log.Info("update node",
		"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)

	// Update in database if configured
	if m.db != nil {
		if err := m.db.UpdateNode(n); err != nil {
			log.Error("failed to update node in database",
				"node", n.Name, slog.Any("error", err))
		}
	}
}

// RemoveNode removes a node from the manager
func (m *Manager) RemoveNode(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.nodes, name)

	log.Info("remove node", "name", name)

	// Remove from database if configured
	if m.db != nil {
		if err := m.db.RemoveNode(name); err != nil {
			log.Error("failed to remove node from database",
				"node", name, slog.Any("error", err))
		}
	}
}

// SetNodes replaces the entire collection of nodes
func (m *Manager) SetNodes(nodeList []Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing nodes
	m.nodes = make(map[string]Node)

	// Add all new nodes
	for _, n := range nodeList {
		m.nodes[n.Name] = n
	}

	log := log
	log.Info("set nodes", "count", len(nodeList))

	// Log first 3 nodes as samples for debugging
	if len(nodeList) > 0 {
		sampleCount := 3
		if len(nodeList) < sampleCount {
			sampleCount = len(nodeList)
		}
		log.Debug("sample nodes:")
		for i := 0; i < sampleCount; i++ {
			n := nodeList[i]
			log.Debug("sample node", "index", i,
				"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)
		}
		if len(nodeList) > sampleCount {
			log.Debug("additional nodes not shown", "count", len(nodeList)-sampleCount)
		}
	}

	// Note: We don't enqueue scans here. CatchUpScans() handles all retry logic at startup.
	// This avoids duplicating work and keeps the retry logic in one place.
}

// GetAllNodes returns all nodes (thread-safe copy)
func (m *Manager) GetAllNodes() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		result = append(result, n)
	}
	return result
}

// GetNodeCount returns the number of nodes
func (m *Manager) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// GetNode retrieves a specific node
func (m *Manager) GetNode(name string) (Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n, exists := m.nodes[name]
	return n, exists
}
