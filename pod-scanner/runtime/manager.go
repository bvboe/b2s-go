package runtime

import (
	"context"
	"fmt"
	"log"
)

// Manager manages container runtime clients and auto-detects available runtime
type Manager struct {
	docker     *DockerClient
	containerd *ContainerDClient
	active     RuntimeClient
}

// NewManager creates a new runtime manager and auto-detects available runtime
// Tries Docker first, then ContainerD
func NewManager() (*Manager, error) {
	mgr := &Manager{}

	// Try Docker first
	mgr.docker = NewDockerClient()
	if mgr.docker.IsAvailable() {
		mgr.active = mgr.docker
		log.Printf("Container runtime detected: Docker")
		return mgr, nil
	}

	// Try ContainerD
	mgr.containerd = NewContainerDClient()
	if mgr.containerd.IsAvailable() {
		mgr.active = mgr.containerd
		log.Printf("Container runtime detected: ContainerD")
		return mgr, nil
	}

	return nil, fmt.Errorf("no container runtime available (tried Docker and ContainerD)")
}

// GenerateSBOM generates an SBOM using the active runtime
func (m *Manager) GenerateSBOM(ctx context.Context, digest string) ([]byte, error) {
	if m.active == nil {
		return nil, fmt.Errorf("no active container runtime")
	}
	return m.active.GenerateSBOM(ctx, digest)
}

// ActiveRuntime returns the name of the active runtime
func (m *Manager) ActiveRuntime() string {
	if m.active == nil {
		return "none"
	}
	return m.active.Name()
}

// Close closes all runtime clients
func (m *Manager) Close() error {
	if m.docker != nil {
		if err := m.docker.Close(); err != nil {
			log.Printf("Warning: failed to close Docker client: %v", err)
		}
	}
	if m.containerd != nil {
		if err := m.containerd.Close(); err != nil {
			log.Printf("Warning: failed to close ContainerD client: %v", err)
		}
	}
	return nil
}
