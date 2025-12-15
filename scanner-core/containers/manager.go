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
}

// Manager handles container instance lifecycle management
type Manager struct {
	mu        sync.RWMutex
	instances map[string]ContainerInstance // key: namespace/pod/container
	db        DatabaseInterface            // optional database persistence
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

	log.Printf("Set container instances: received %d instances", len(instances))
	for i, instance := range instances {
		log.Printf("  [%d] namespace=%s, pod=%s, container=%s, image=%s:%s (digest=%s)",
			i, instance.ID.Namespace, instance.ID.Pod, instance.ID.Container,
			instance.Image.Repository, instance.Image.Tag, instance.Image.Digest)
	}

	// Update database if configured
	if m.db != nil {
		if err := m.db.SetInstances(instances); err != nil {
			log.Printf("Error setting instances in database: %v", err)
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
