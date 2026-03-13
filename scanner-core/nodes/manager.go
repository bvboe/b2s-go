package nodes

import (
	"log"
	"sync"
)

// NodeDatabaseInterface defines the interface for node database operations
type NodeDatabaseInterface interface {
	AddNode(n Node) (bool, error)
	UpdateNode(n Node) error
	RemoveNode(name string) error
	GetNode(name string) (*NodeWithStatus, error)
	GetAllNodes() ([]NodeWithStatus, error)
	GetNodeScanStatus(name string) (string, error)
	IsNodeScanComplete(name string) (bool, error)
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
	log.Println("Node manager: database persistence enabled")
}

// SetScanQueue configures the manager to use a scan queue for host SBOM generation
// After setting the queue, it enqueues scans for any nodes that were discovered
// before the queue was connected (catch-up for initial sync)
func (m *Manager) SetScanQueue(queue NodeScanQueueInterface) {
	m.mu.Lock()
	m.scanQueue = queue
	log.Println("Node manager: scan queue enabled")

	// Catch-up: enqueue scans for nodes discovered before queue was connected
	if m.db != nil && len(m.nodes) > 0 {
		log.Printf("Checking %d nodes for pending scans...", len(m.nodes))

		pendingCount := 0
		for _, n := range m.nodes {
			// Check and enqueue scan with retry logic
			m.mu.Unlock()
			m.checkAndEnqueueScan(n)
			m.mu.Lock()
			pendingCount++
		}

		log.Printf("Queued catch-up scans for %d nodes", pendingCount)
	}
	m.mu.Unlock()
}

// AddNode adds or updates a node in the manager
func (m *Manager) AddNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[n.Name] = n

	log.Printf("Add node: name=%s, hostname=%s, os=%s, arch=%s",
		n.Name, n.Hostname, n.OSRelease, n.Architecture)

	// Persist to database if configured
	if m.db != nil {
		if _, err := m.db.AddNode(n); err != nil {
			log.Printf("Error adding node to database: %v", err)
			return
		}

		// Check if this node needs scanning
		if m.scanQueue != nil {
			m.checkAndEnqueueScan(n)
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
		log.Printf("Update node: node %s not found, adding instead", n.Name)
	}

	m.nodes[n.Name] = n

	log.Printf("Update node: name=%s, hostname=%s, os=%s, arch=%s",
		n.Name, n.Hostname, n.OSRelease, n.Architecture)

	// Update in database if configured
	if m.db != nil {
		if err := m.db.UpdateNode(n); err != nil {
			log.Printf("Error updating node in database: %v", err)
		}
	}
}

// RemoveNode removes a node from the manager
func (m *Manager) RemoveNode(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.nodes, name)

	log.Printf("Remove node: name=%s", name)

	// Remove from database if configured
	if m.db != nil {
		if err := m.db.RemoveNode(name); err != nil {
			log.Printf("Error removing node from database: %v", err)
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

	log.Printf("Set nodes: %d nodes", len(nodeList))

	// Log first 3 nodes as samples for debugging
	if len(nodeList) > 0 {
		sampleCount := 3
		if len(nodeList) < sampleCount {
			sampleCount = len(nodeList)
		}
		log.Printf("Sample nodes:")
		for i := 0; i < sampleCount; i++ {
			n := nodeList[i]
			log.Printf("  [%d] name=%s, hostname=%s, os=%s, arch=%s",
				i, n.Name, n.Hostname, n.OSRelease, n.Architecture)
		}
		if len(nodeList) > sampleCount {
			log.Printf("  ... and %d more nodes", len(nodeList)-sampleCount)
		}
	}

	// Enqueue scan jobs for nodes that need scanning
	if m.db != nil && m.scanQueue != nil {
		for _, n := range nodeList {
			m.checkAndEnqueueScan(n)
		}
	}
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

// checkAndEnqueueScan checks if a node needs scanning and enqueues it
func (m *Manager) checkAndEnqueueScan(n Node) {
	scanStatus, err := m.db.GetNodeScanStatus(n.Name)
	if err != nil {
		log.Printf("Error checking scan status for node %s: %v", n.Name, err)
		return
	}

	// Handle different scan statuses
	switch scanStatus {
	case "pending":
		// New node, enqueue normal scan
		log.Printf("Enqueuing scan for new node: %s", n.Name)
		m.scanQueue.EnqueueHostScan(n.Name)

	case "failed":
		// Previous scan failed, retry with force scan
		log.Printf("Retrying failed scan for node: %s", n.Name)
		m.scanQueue.EnqueueHostForceScan(n.Name)

	case "scanned", "completed":
		// Check if data is actually complete
		isComplete, err := m.db.IsNodeScanComplete(n.Name)
		if err != nil {
			log.Printf("Error checking scan completeness for node %s: %v", n.Name, err)
			return
		}
		if !isComplete {
			// Data is incomplete, retry with force scan
			log.Printf("Retrying scan for node with incomplete data: %s", n.Name)
			m.scanQueue.EnqueueHostForceScan(n.Name)
		}
		// If complete, no action needed

	case "scanning", "generating_sbom", "scanning_vulnerabilities":
		// Node is in an intermediate state (previous scan was interrupted)
		log.Printf("Retrying interrupted scan for node: %s", n.Name)
		m.scanQueue.EnqueueHostForceScan(n.Name)
	}
}
