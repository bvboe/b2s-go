package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

func TestAddInstance(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_instances_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Test adding a new instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	isNew, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}
	if !isNew {
		t.Error("Expected AddInstance to return true for new instance")
	}

	// Verify the instance was added
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get all instances: %v", err)
	}

	instanceRows, ok := allInstances.([]ContainerInstanceRow)
	if !ok {
		t.Fatalf("Expected []ContainerInstanceRow, got %T", allInstances)
	}

	if len(instanceRows) != 1 {
		t.Errorf("Expected 1 instance, got %d", len(instanceRows))
	}

	if instanceRows[0].Namespace != "default" || instanceRows[0].Pod != "test-pod" {
		t.Errorf("Instance has wrong values: %+v", instanceRows[0])
	}
}

func TestAddInstanceDuplicate(t *testing.T) {
	dbPath := "/tmp/test_instances_dup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	// Add instance first time
	isNew, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}
	if !isNew {
		t.Error("Expected first add to return true")
	}

	// Add same instance again (should not be considered new)
	isNew, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add duplicate instance: %v", err)
	}
	if isNew {
		t.Error("Expected duplicate add to return false")
	}
}

func TestAddInstanceWithImageUpdate(t *testing.T) {
	dbPath := "/tmp/test_instances_update_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add instance with one image
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.20",
			Digest:     "sha256:old123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	isNew, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}
	if !isNew {
		t.Error("Expected first add to return true")
	}

	// Update instance with different image
	instance.Image.Tag = "1.21"
	instance.Image.Digest = "sha256:new456"

	isNew, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to update instance: %v", err)
	}
	if !isNew {
		t.Error("Expected image update to return true")
	}

	// Verify the instance was updated
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get all instances: %v", err)
	}

	instanceRows := allInstances.([]ContainerInstanceRow)
	if len(instanceRows) != 1 {
		t.Errorf("Expected 1 instance after update, got %d", len(instanceRows))
	}

	if instanceRows[0].Tag != "1.21" || instanceRows[0].Digest != "sha256:new456" {
		t.Errorf("Instance not updated correctly: tag=%s, digest=%s", instanceRows[0].Tag, instanceRows[0].Digest)
	}
}

func TestAddInstanceValidation(t *testing.T) {
	dbPath := "/tmp/test_instances_validation_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	tests := []struct {
		name        string
		instance    containers.ContainerInstance
		expectError bool
	}{
		{
			name: "missing digest",
			instance: containers.ContainerInstance{
				ID: containers.ContainerInstanceID{
					Namespace: "default",
					Pod:       "test-pod",
					Container: "nginx",
				},
				Image: containers.ImageID{
					Repository: "nginx",
					Tag:        "1.21",
					Digest:     "", // Missing digest
				},
			},
			expectError: true,
		},
		{
			name: "missing repository",
			instance: containers.ContainerInstance{
				ID: containers.ContainerInstanceID{
					Namespace: "default",
					Pod:       "test-pod",
					Container: "nginx",
				},
				Image: containers.ImageID{
					Repository: "", // Missing repository
					Tag:        "1.21",
					Digest:     "sha256:abc123",
				},
			},
			expectError: true,
		},
		{
			name: "missing namespace",
			instance: containers.ContainerInstance{
				ID: containers.ContainerInstanceID{
					Namespace: "", // Missing namespace
					Pod:       "test-pod",
					Container: "nginx",
				},
				Image: containers.ImageID{
					Repository: "nginx",
					Tag:        "1.21",
					Digest:     "sha256:abc123",
				},
			},
			expectError: true,
		},
		{
			name: "valid instance",
			instance: containers.ContainerInstance{
				ID: containers.ContainerInstanceID{
					Namespace: "default",
					Pod:       "test-pod",
					Container: "nginx",
				},
				Image: containers.ImageID{
					Repository: "nginx",
					Tag:        "1.21",
					Digest:     "sha256:abc123",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := db.AddInstance(tt.instance)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestRemoveInstance(t *testing.T) {
	dbPath := "/tmp/test_instances_remove_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Remove instance
	err = db.RemoveInstance(instance.ID)
	if err != nil {
		t.Fatalf("Failed to remove instance: %v", err)
	}

	// Verify it's gone
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get all instances: %v", err)
	}

	instanceRows := allInstances.([]ContainerInstanceRow)
	if len(instanceRows) != 0 {
		t.Errorf("Expected 0 instances after removal, got %d", len(instanceRows))
	}
}

func TestSetInstances(t *testing.T) {
	dbPath := "/tmp/test_instances_set_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add some initial instances
	instance1 := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "old-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.20",
			Digest:     "sha256:old123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(instance1)
	if err != nil {
		t.Fatalf("Failed to add initial instance: %v", err)
	}

	// Set new instances (should replace old ones)
	newInstances := []containers.ContainerInstance{
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "new-pod-1",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:new123",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "kube-system",
				Pod:       "new-pod-2",
				Container: "envoy",
			},
			Image: containers.ImageID{
				Repository: "envoy",
				Tag:        "v1.20",
				Digest:     "sha256:envoy456",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "containerd",
		},
	}

	err = db.SetInstances(newInstances)
	if err != nil {
		t.Fatalf("Failed to set instances: %v", err)
	}

	// Verify new instances
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get all instances: %v", err)
	}

	instanceRows := allInstances.([]ContainerInstanceRow)
	if len(instanceRows) != 2 {
		t.Errorf("Expected 2 instances after SetInstances, got %d", len(instanceRows))
	}

	// Verify old instance is gone and new instances exist
	foundNewPod1 := false
	foundNewPod2 := false
	foundOldPod := false

	for _, row := range instanceRows {
		if row.Pod == "old-pod" {
			foundOldPod = true
		}
		if row.Pod == "new-pod-1" {
			foundNewPod1 = true
		}
		if row.Pod == "new-pod-2" {
			foundNewPod2 = true
		}
	}

	if foundOldPod {
		t.Error("Old instance still exists after SetInstances")
	}
	if !foundNewPod1 || !foundNewPod2 {
		t.Error("New instances not found after SetInstances")
	}
}

func TestSetInstancesValidation(t *testing.T) {
	dbPath := "/tmp/test_instances_set_validation_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Try to set instances with one invalid instance
	instances := []containers.ContainerInstance{
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "valid-pod",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:valid123",
			},
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "invalid-pod",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "", // Missing digest
			},
		},
	}

	err = db.SetInstances(instances)
	if err == nil {
		t.Error("Expected error when setting instances with invalid data")
	}

	// Verify no instances were added (transaction should have rolled back)
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get all instances: %v", err)
	}

	instanceRows := allInstances.([]ContainerInstanceRow)
	if len(instanceRows) != 0 {
		t.Errorf("Expected 0 instances after failed SetInstances, got %d", len(instanceRows))
	}
}
