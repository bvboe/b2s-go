package containers

import (
	"log"
	"sync"
)

// ReconciliationStats holds statistics about a reconciliation operation
type ReconciliationStats struct {
	InstancesAdded   int // Number of new container instances added
	InstancesRemoved int // Number of container instances removed
	ImagesAdded      int // Number of new container images discovered
}

// DatabaseInterface defines the interface for database operations
type DatabaseInterface interface {
	AddInstance(instance ContainerInstance) (bool, error)
	RemoveInstance(id ContainerInstanceID) error
	SetInstances(instances []ContainerInstance) (*ReconciliationStats, error)
	GetImageScanStatus(digest string) (string, error)
	IsScanDataComplete(digest string) (bool, error)
}

// ScanQueueInterface defines the interface for enqueuing scan jobs
type ScanQueueInterface interface {
	EnqueueScan(image ImageID, nodeName string, containerRuntime string)
	EnqueueForceScan(image ImageID, nodeName string, containerRuntime string)
}

// RefreshTrigger defines the interface for triggering container instance refreshes
// This is implemented by the agent or k8s-scan-server to provide running container data
type RefreshTrigger interface {
	// TriggerRefresh signals that scanner-core wants updated container instance data
	// The implementation should gather current container data and call SetContainerInstances
	TriggerRefresh() error
}

// Manager handles container instance lifecycle management
type Manager struct {
	mu        sync.RWMutex
	instances map[string]ContainerInstance // key: namespace/pod/container
	db        DatabaseInterface            // optional database persistence
	scanQueue ScanQueueInterface           // optional scan queue for SBOM generation
}

// NewManager creates a new container instance manager
func NewManager() *Manager {
	return &Manager{
		instances: make(map[string]ContainerInstance),
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
	if m.db != nil && len(m.instances) > 0 {
		log.Printf("Checking %d instances for pending scans...", len(m.instances))

		// Track unique images to avoid duplicate scan jobs
		seenDigests := make(map[string]bool)
		pendingCount := 0

		for _, instance := range m.instances {
			if instance.Image.Digest == "" {
				continue
			}
			if seenDigests[instance.Image.Digest] {
				continue
			}
			seenDigests[instance.Image.Digest] = true

			// Check and enqueue scan with retry logic
			// Note: checkAndEnqueueScan needs the lock released
			m.mu.Unlock()
			m.checkAndEnqueueScan(instance)
			m.mu.Lock()
			pendingCount++
		}

		log.Printf("Queued catch-up scans for %d unique images", pendingCount)
	}
	m.mu.Unlock()
}

// makeKey creates a unique key for a container instance
func makeKey(namespace, pod, container string) string {
	return namespace + "/" + pod + "/" + container
}

// AddContainerInstance adds a single container instance to the manager
func (m *Manager) AddContainerInstance(instance ContainerInstance) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
	m.instances[key] = instance

	log.Printf("Add container instance: namespace=%s, pod=%s, container=%s, image=%s:%s (digest=%s)",
		instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
		instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)

	// Persist to database if configured
	if m.db != nil {
		if _, err := m.db.AddInstance(instance); err != nil {
			log.Printf("Error adding instance to database: %v", err)
			return
		}

		// Check if this image needs scanning or retrying
		if m.scanQueue != nil && instance.Image.Digest != "" {
			m.checkAndEnqueueScan(instance)
		}
	}
}

// RemoveContainerInstance removes a single container instance from the manager
func (m *Manager) RemoveContainerInstance(id ContainerInstanceID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(id.Namespace, id.Pod, id.Container)
	delete(m.instances, key)

	log.Printf("Remove container instance: namespace=%s, pod=%s, container=%s",
		id.Namespace, id.Pod, id.Container)

	// Remove from database if configured
	if m.db != nil {
		if err := m.db.RemoveInstance(id); err != nil {
			log.Printf("Error removing instance from database: %v", err)
		}
	}
}

// SetContainerInstances replaces the entire collection of container instances
func (m *Manager) SetContainerInstances(instances []ContainerInstance) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing instances
	m.instances = make(map[string]ContainerInstance)

	// Add all new instances
	for _, instance := range instances {
		key := makeKey(instance.ID.Namespace, instance.ID.Pod, instance.ID.Container)
		m.instances[key] = instance
	}

	// Log summary instead of every instance (to reduce noise in large clusters)
	uniqueImages := make(map[string]bool)
	uniqueNodes := make(map[string]bool)
	for _, instance := range instances {
		if instance.Image.Digest != "" {
			uniqueImages[instance.Image.Digest] = true
		}
		if instance.NodeName != "" {
			uniqueNodes[instance.NodeName] = true
		}
	}

	log.Printf("Set container instances: %d instances, %d unique images, %d nodes",
		len(instances), len(uniqueImages), len(uniqueNodes))

	// Log first 3 instances as samples for debugging (only if we have instances)
	if len(instances) > 0 {
		sampleCount := 3
		if len(instances) < sampleCount {
			sampleCount = len(instances)
		}
		log.Printf("Sample instances:")
		for i := 0; i < sampleCount; i++ {
			instance := instances[i]
			log.Printf("  [%d] ns=%s, pod=%s, container=%s, image=%s:%s, node=%s",
				i, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
				instance.Image.Repository, instance.Image.Tag, instance.NodeName)
		}
		if len(instances) > sampleCount {
			log.Printf("  ... and %d more instances", len(instances)-sampleCount)
		}
	}

	// Update database if configured
	if m.db != nil {
		stats, err := m.db.SetInstances(instances)
		if err != nil {
			log.Printf("Error setting instances in database: %v", err)
			return
		}

		// Log reconciliation summary
		if stats != nil {
			log.Printf("Reconciliation summary: %d instances added, %d instances removed, %d new images discovered",
				stats.InstancesAdded, stats.InstancesRemoved, stats.ImagesAdded)
		}

		// Enqueue scan jobs for images that need scanning or retrying
		if m.scanQueue != nil {
			// Track unique images to avoid duplicate scan jobs
			seenDigests := make(map[string]bool)

			for _, instance := range instances {
				if instance.Image.Digest == "" {
					continue // Skip instances without digest
				}

				// Skip if we've already processed this digest
				if seenDigests[instance.Image.Digest] {
					continue
				}
				seenDigests[instance.Image.Digest] = true

				// Check and enqueue scan with retry logic
				m.checkAndEnqueueScan(instance)
			}
		}
	}
}

// GetAllInstances returns all container instances (thread-safe copy)
func (m *Manager) GetAllInstances() []ContainerInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	instances := make([]ContainerInstance, 0, len(m.instances))
	for _, instance := range m.instances {
		instances = append(instances, instance)
	}
	return instances
}

// GetInstanceCount returns the number of container instances
func (m *Manager) GetInstanceCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.instances)
}

// GetInstance retrieves a specific container instance
func (m *Manager) GetInstance(namespace, pod, container string) (ContainerInstance, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := makeKey(namespace, pod, container)
	instance, exists := m.instances[key]
	return instance, exists
}

// checkAndEnqueueScan checks if an image needs scanning and enqueues it with appropriate flags
// This method handles retrying failed or incomplete scans
func (m *Manager) checkAndEnqueueScan(instance ContainerInstance) {
	scanStatus, err := m.db.GetImageScanStatus(instance.Image.Digest)
	if err != nil {
		log.Printf("Error checking scan status for %s: %v", instance.Image.Digest, err)
		return
	}

	// Handle different scan statuses
	switch scanStatus {
	case "pending":
		// New image, enqueue normal scan
		log.Printf("Enqueuing scan for new image: %s:%s (digest=%s)",
			instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
		m.scanQueue.EnqueueScan(instance.Image, instance.NodeName, instance.ContainerRuntime)

	case "failed":
		// Previous scan failed, retry with force scan
		log.Printf("Retrying failed scan for image: %s:%s (digest=%s)",
			instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
		m.scanQueue.EnqueueForceScan(instance.Image, instance.NodeName, instance.ContainerRuntime)

	case "scanned":
		// Check if data is actually complete
		isComplete, err := m.db.IsScanDataComplete(instance.Image.Digest)
		if err != nil {
			log.Printf("Error checking scan data completeness for %s: %v", instance.Image.Digest, err)
			return
		}
		if !isComplete {
			// Data is incomplete, retry with force scan
			log.Printf("Retrying scan for image with incomplete data: %s:%s (digest=%s)",
				instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
			m.scanQueue.EnqueueForceScan(instance.Image, instance.NodeName, instance.ContainerRuntime)
		}
		// If complete, no action needed

	case "scanning":
		// Image is in an intermediate state (generating_sbom).
		// This typically means a previous scan was interrupted (e.g., pod restart).
		// Re-enqueue with force scan to resume/restart the scan.
		log.Printf("Retrying interrupted scan for image: %s:%s (digest=%s)",
			instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
		m.scanQueue.EnqueueForceScan(instance.Image, instance.NodeName, instance.ContainerRuntime)
	}
}
