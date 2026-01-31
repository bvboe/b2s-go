package containers

import (
	"log"
	"sync"
)

// ReconciliationStats holds statistics about a reconciliation operation
type ReconciliationStats struct {
	ContainersAdded   int // Number of new containers added
	ContainersRemoved int // Number of containers removed
	ImagesAdded       int // Number of new images discovered
}

// DatabaseInterface defines the interface for database operations
type DatabaseInterface interface {
	AddContainer(c Container) (bool, error)
	RemoveContainer(id ContainerID) error
	SetContainers(containers []Container) (*ReconciliationStats, error)
	GetImageScanStatus(digest string) (string, error)
	IsScanDataComplete(digest string) (bool, error)
}

// ScanQueueInterface defines the interface for enqueuing scan jobs
type ScanQueueInterface interface {
	EnqueueScan(image ImageID, nodeName string, containerRuntime string)
	EnqueueForceScan(image ImageID, nodeName string, containerRuntime string)
}

// RefreshTrigger defines the interface for triggering container refreshes
// This is implemented by the agent or k8s-scan-server to provide running container data
type RefreshTrigger interface {
	// TriggerRefresh signals that scanner-core wants updated container data
	// The implementation should gather current container data and call SetContainers
	TriggerRefresh() error
}

// Manager handles container lifecycle management
type Manager struct {
	mu         sync.RWMutex
	containers map[string]Container // key: namespace/pod/name
	db         DatabaseInterface    // optional database persistence
	scanQueue  ScanQueueInterface   // optional scan queue for SBOM generation
}

// NewManager creates a new container manager
func NewManager() *Manager {
	return &Manager{
		containers: make(map[string]Container),
	}
}

// SetDatabase configures the manager to use a database for persistence
func (m *Manager) SetDatabase(db DatabaseInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
	log.Println("Container manager: database persistence enabled")
}

// SetScanQueue configures the manager to use a scan queue for SBOM generation
// After setting the queue, it enqueues scans for any images that were discovered
// before the queue was connected (catch-up for initial sync)
func (m *Manager) SetScanQueue(queue ScanQueueInterface) {
	m.mu.Lock()
	m.scanQueue = queue
	log.Println("Container manager: scan queue enabled")

	// Catch-up: enqueue scans for images discovered before queue was connected
	// This handles images from initial sync that couldn't be enqueued
	if m.db != nil && len(m.containers) > 0 {
		log.Printf("Checking %d containers for pending scans...", len(m.containers))

		// Track unique images to avoid duplicate scan jobs
		seenDigests := make(map[string]bool)
		pendingCount := 0

		for _, c := range m.containers {
			if c.Image.Digest == "" {
				continue
			}
			if seenDigests[c.Image.Digest] {
				continue
			}
			seenDigests[c.Image.Digest] = true

			// Check and enqueue scan with retry logic
			// Note: checkAndEnqueueScan needs the lock released
			m.mu.Unlock()
			m.checkAndEnqueueScan(c)
			m.mu.Lock()
			pendingCount++
		}

		log.Printf("Queued catch-up scans for %d unique images", pendingCount)
	}
	m.mu.Unlock()
}

// makeKey creates a unique key for a container
func makeKey(namespace, pod, name string) string {
	return namespace + "/" + pod + "/" + name
}

// AddContainer adds a single container to the manager
func (m *Manager) AddContainer(c Container) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(c.ID.Namespace, c.ID.Pod, c.ID.Name)
	m.containers[key] = c

	log.Printf("Add container: namespace=%s, pod=%s, name=%s, image=%s (digest=%s)",
		c.ID.Namespace, c.ID.Pod, c.ID.Name,
		c.Image.Reference, c.Image.Digest)

	// Persist to database if configured
	if m.db != nil {
		if _, err := m.db.AddContainer(c); err != nil {
			log.Printf("Error adding container to database: %v", err)
			return
		}

		// Check if this image needs scanning or retrying
		if m.scanQueue != nil && c.Image.Digest != "" {
			m.checkAndEnqueueScan(c)
		}
	}
}

// RemoveContainer removes a single container from the manager
func (m *Manager) RemoveContainer(id ContainerID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(id.Namespace, id.Pod, id.Name)
	delete(m.containers, key)

	log.Printf("Remove container: namespace=%s, pod=%s, name=%s",
		id.Namespace, id.Pod, id.Name)

	// Remove from database if configured
	if m.db != nil {
		if err := m.db.RemoveContainer(id); err != nil {
			log.Printf("Error removing container from database: %v", err)
		}
	}
}

// SetContainers replaces the entire collection of containers
func (m *Manager) SetContainers(containers []Container) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing containers
	m.containers = make(map[string]Container)

	// Add all new containers
	for _, c := range containers {
		key := makeKey(c.ID.Namespace, c.ID.Pod, c.ID.Name)
		m.containers[key] = c
	}

	// Log summary instead of every container (to reduce noise in large clusters)
	uniqueImages := make(map[string]bool)
	uniqueNodes := make(map[string]bool)
	for _, c := range containers {
		if c.Image.Digest != "" {
			uniqueImages[c.Image.Digest] = true
		}
		if c.NodeName != "" {
			uniqueNodes[c.NodeName] = true
		}
	}

	log.Printf("Set containers: %d containers, %d unique images, %d nodes",
		len(containers), len(uniqueImages), len(uniqueNodes))

	// Log first 3 containers as samples for debugging (only if we have containers)
	if len(containers) > 0 {
		sampleCount := 3
		if len(containers) < sampleCount {
			sampleCount = len(containers)
		}
		log.Printf("Sample containers:")
		for i := 0; i < sampleCount; i++ {
			c := containers[i]
			log.Printf("  [%d] ns=%s, pod=%s, name=%s, image=%s, node=%s",
				i, c.ID.Namespace, c.ID.Pod, c.ID.Name,
				c.Image.Reference, c.NodeName)
		}
		if len(containers) > sampleCount {
			log.Printf("  ... and %d more containers", len(containers)-sampleCount)
		}
	}

	// Update database if configured
	if m.db != nil {
		stats, err := m.db.SetContainers(containers)
		if err != nil {
			log.Printf("Error setting containers in database: %v", err)
			return
		}

		// Log reconciliation summary
		if stats != nil {
			log.Printf("Reconciliation summary: %d containers added, %d containers removed, %d new images discovered",
				stats.ContainersAdded, stats.ContainersRemoved, stats.ImagesAdded)
		}

		// Enqueue scan jobs for images that need scanning or retrying
		if m.scanQueue != nil {
			// Track unique images to avoid duplicate scan jobs
			seenDigests := make(map[string]bool)

			for _, c := range containers {
				if c.Image.Digest == "" {
					continue // Skip containers without digest
				}

				// Skip if we've already processed this digest
				if seenDigests[c.Image.Digest] {
					continue
				}
				seenDigests[c.Image.Digest] = true

				// Check and enqueue scan with retry logic
				m.checkAndEnqueueScan(c)
			}
		}
	}
}

// GetAllContainers returns all containers (thread-safe copy)
func (m *Manager) GetAllContainers() []Container {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}
	return result
}

// GetContainerCount returns the number of containers
func (m *Manager) GetContainerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.containers)
}

// GetContainer retrieves a specific container
func (m *Manager) GetContainer(namespace, pod, name string) (Container, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := makeKey(namespace, pod, name)
	c, exists := m.containers[key]
	return c, exists
}

// checkAndEnqueueScan checks if an image needs scanning and enqueues it with appropriate flags
// This method handles retrying failed or incomplete scans
func (m *Manager) checkAndEnqueueScan(c Container) {
	scanStatus, err := m.db.GetImageScanStatus(c.Image.Digest)
	if err != nil {
		log.Printf("Error checking scan status for %s: %v", c.Image.Digest, err)
		return
	}

	// Handle different scan statuses
	switch scanStatus {
	case "pending":
		// New image, enqueue normal scan
		log.Printf("Enqueuing scan for new image: %s (digest=%s)",
			c.Image.Reference, c.Image.Digest)
		m.scanQueue.EnqueueScan(c.Image, c.NodeName, c.ContainerRuntime)

	case "failed":
		// Previous scan failed, retry with force scan
		log.Printf("Retrying failed scan for image: %s (digest=%s)",
			c.Image.Reference, c.Image.Digest)
		m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)

	case "scanned":
		// Check if data is actually complete
		isComplete, err := m.db.IsScanDataComplete(c.Image.Digest)
		if err != nil {
			log.Printf("Error checking scan data completeness for %s: %v", c.Image.Digest, err)
			return
		}
		if !isComplete {
			// Data is incomplete, retry with force scan
			log.Printf("Retrying scan for image with incomplete data: %s (digest=%s)",
				c.Image.Reference, c.Image.Digest)
			m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
		}
		// If complete, no action needed

	case "scanning":
		// Image is in an intermediate state (generating_sbom).
		// This typically means a previous scan was interrupted (e.g., pod restart).
		// Re-enqueue with force scan to resume/restart the scan.
		log.Printf("Retrying interrupted scan for image: %s (digest=%s)",
			c.Image.Reference, c.Image.Digest)
		m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
	}
}
