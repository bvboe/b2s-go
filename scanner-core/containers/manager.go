package containers

import (
	"log"
	"sync"
)

// DatabaseInterface defines the interface for database operations
type DatabaseInterface interface {
	AddInstance(instance ContainerInstance) (bool, error)
	RemoveInstance(id ContainerInstanceID) error
	SetInstances(instances []ContainerInstance) error
	GetImageScanStatus(digest string) (string, error)
	IsScanDataComplete(digest string) (bool, error)
}

// ScanQueueInterface defines the interface for enqueuing scan jobs
type ScanQueueInterface interface {
	EnqueueScan(image ImageID, nodeName string, containerRuntime string)
	EnqueueForceScan(image ImageID, nodeName string, containerRuntime string)
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
func (m *Manager) SetScanQueue(queue ScanQueueInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanQueue = queue
	log.Println("Container manager: scan queue enabled")
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
		if err := m.db.SetInstances(instances); err != nil {
			log.Printf("Error setting instances in database: %v", err)
			return
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
		// Scan already in progress, no action needed
		log.Printf("Scan already in progress for image: %s:%s (digest=%s)",
			instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
	}
}
