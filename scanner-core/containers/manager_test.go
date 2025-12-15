package containers

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.GetInstanceCount() != 0 {
		t.Errorf("Expected 0 instances, got %d", m.GetInstanceCount())
	}
}

func TestAddContainerInstance(t *testing.T) {
	m := NewManager()

	instance := ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod-123",
			Container: "app",
		},
		Image: ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:abc123",
		},
	}

	m.AddContainerInstance(instance)

	if m.GetInstanceCount() != 1 {
		t.Errorf("Expected 1 instance, got %d", m.GetInstanceCount())
	}

	retrieved, exists := m.GetInstance("default", "test-pod-123", "app")
	if !exists {
		t.Fatal("Instance not found after adding")
	}

	if retrieved.Image.Repository != "nginx" || retrieved.Image.Tag != "1.21" {
		t.Errorf("Retrieved instance has wrong values: %+v", retrieved)
	}
}

func TestAddMultipleInstances(t *testing.T) {
	m := NewManager()

	instances := []ContainerInstance{
		{
			ID: ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-1",
				Container: "app",
			},
			Image: ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:abc123",
			},
		},
		{
			ID: ContainerInstanceID{
				Namespace: "kube-system",
				Pod:       "pod-2",
				Container: "proxy",
			},
			Image: ImageID{
				Repository: "envoy",
				Tag:        "v1.20",
				Digest:     "sha256:def456",
			},
		},
		{
			ID: ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-3",
				Container: "sidecar",
			},
			Image: ImageID{
				Repository: "busybox",
				Tag:        "latest",
				Digest:     "sha256:ghi789",
			},
		},
	}

	for _, instance := range instances {
		m.AddContainerInstance(instance)
	}

	if m.GetInstanceCount() != 3 {
		t.Errorf("Expected 3 instances, got %d", m.GetInstanceCount())
	}
}

func TestRemoveContainerInstance(t *testing.T) {
	m := NewManager()

	instance := ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "app",
		},
	}

	m.AddContainerInstance(instance)
	if m.GetInstanceCount() != 1 {
		t.Fatalf("Expected 1 instance after add, got %d", m.GetInstanceCount())
	}

	m.RemoveContainerInstance(instance.ID)
	if m.GetInstanceCount() != 0 {
		t.Errorf("Expected 0 instances after remove, got %d", m.GetInstanceCount())
	}

	_, exists := m.GetInstance("default", "test-pod", "app")
	if exists {
		t.Error("Instance still exists after removal")
	}
}

func TestSetContainerInstances(t *testing.T) {
	m := NewManager()

	// Add some initial instances
	m.AddContainerInstance(ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "old-pod",
			Container: "old-container",
		},
	})

	if m.GetInstanceCount() != 1 {
		t.Fatalf("Expected 1 instance initially, got %d", m.GetInstanceCount())
	}

	// Set new instances (should replace old ones)
	newInstances := []ContainerInstance{
		{
			ID: ContainerInstanceID{
				Namespace: "default",
				Pod:       "new-pod-1",
				Container: "app",
			},
			Image: ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:abc123",
			},
		},
		{
			ID: ContainerInstanceID{
				Namespace: "kube-system",
				Pod:       "new-pod-2",
				Container: "proxy",
			},
			Image: ImageID{
				Repository: "envoy",
				Tag:        "v1.20",
				Digest:     "sha256:def456",
			},
		},
	}

	m.SetContainerInstances(newInstances)

	if m.GetInstanceCount() != 2 {
		t.Errorf("Expected 2 instances after set, got %d", m.GetInstanceCount())
	}

	// Old instance should be gone
	_, exists := m.GetInstance("default", "old-pod", "old-container")
	if exists {
		t.Error("Old instance still exists after SetContainerInstances")
	}

	// New instances should exist
	_, exists = m.GetInstance("default", "new-pod-1", "app")
	if !exists {
		t.Error("New instance 1 not found")
	}

	_, exists = m.GetInstance("kube-system", "new-pod-2", "proxy")
	if !exists {
		t.Error("New instance 2 not found")
	}
}

func TestSetContainerInstancesEmpty(t *testing.T) {
	m := NewManager()

	// Add some instances
	m.AddContainerInstance(ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "pod-1",
			Container: "app",
		},
	})
	m.AddContainerInstance(ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "pod-2",
			Container: "app",
		},
	})

	if m.GetInstanceCount() != 2 {
		t.Fatalf("Expected 2 instances, got %d", m.GetInstanceCount())
	}

	// Set empty collection (should clear all)
	m.SetContainerInstances([]ContainerInstance{})

	if m.GetInstanceCount() != 0 {
		t.Errorf("Expected 0 instances after setting empty collection, got %d", m.GetInstanceCount())
	}
}

func TestGetAllInstances(t *testing.T) {
	m := NewManager()

	instances := []ContainerInstance{
		{
			ID: ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-1",
				Container: "app",
			},
		},
		{
			ID: ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-2",
				Container: "app",
			},
		},
	}

	for _, instance := range instances {
		m.AddContainerInstance(instance)
	}

	all := m.GetAllInstances()
	if len(all) != 2 {
		t.Errorf("Expected 2 instances from GetAllInstances, got %d", len(all))
	}
}

func TestConcurrency(t *testing.T) {
	m := NewManager()

	// Test concurrent adds
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			instance := ContainerInstance{
				ID: ContainerInstanceID{
					Namespace: "default",
					Pod:       "concurrent-pod",
					Container: string(rune('a' + id)),
				},
			}
			m.AddContainerInstance(instance)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	if m.GetInstanceCount() != 10 {
		t.Errorf("Expected 10 instances after concurrent adds, got %d", m.GetInstanceCount())
	}
}

func TestUpdateExistingInstance(t *testing.T) {
	m := NewManager()

	// Add initial instance
	instance := ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "app",
		},
		Image: ImageID{
			Repository: "nginx",
			Tag:        "1.20",
			Digest:     "sha256:old123",
		},
	}
	m.AddContainerInstance(instance)

	// Update with new tag and image ID
	updated := ContainerInstance{
		ID: ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "app",
		},
		Image: ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:new456",
		},
	}
	m.AddContainerInstance(updated)

	// Should still have only 1 instance (updated)
	if m.GetInstanceCount() != 1 {
		t.Errorf("Expected 1 instance, got %d", m.GetInstanceCount())
	}

	retrieved, _ := m.GetInstance("default", "test-pod", "app")
	if retrieved.Image.Tag != "1.21" || retrieved.Image.Digest != "sha256:new456" {
		t.Errorf("Instance not updated correctly: %+v", retrieved)
	}
}
