package integration_test

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

// MockScanQueue implements ScanQueueInterface for testing
type MockScanQueue struct {
	enqueuedScans      []EnqueuedScan
	enqueuedForceScans []EnqueuedScan
}

type EnqueuedScan struct {
	Image            containers.ImageID
	NodeName         string
	ContainerRuntime string
}

func (m *MockScanQueue) EnqueueScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedScans = append(m.enqueuedScans, EnqueuedScan{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

func (m *MockScanQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedForceScans = append(m.enqueuedForceScans, EnqueuedScan{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

func TestManagerWithDatabase(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_db_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager and set database
	manager := containers.NewManager()
	manager.SetDatabase(db)

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

	manager.AddContainerInstance(instance)

	// Verify instance is in manager
	if manager.GetInstanceCount() != 1 {
		t.Errorf("Expected 1 instance in manager, got %d", manager.GetInstanceCount())
	}

	// Verify instance is in database
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get instances from database: %v", err)
	}

	instanceRows := allInstances.([]database.ContainerInstanceRow)
	if len(instanceRows) != 1 {
		t.Errorf("Expected 1 instance in database, got %d", len(instanceRows))
	}

	if instanceRows[0].Namespace != "default" || instanceRows[0].Pod != "test-pod" {
		t.Errorf("Instance in database has wrong values: %+v", instanceRows[0])
	}
}

func TestManagerWithScanQueue(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add instance with new image
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

	manager.AddContainerInstance(instance)

	// Give it a moment to process
	time.Sleep(100 * time.Millisecond)

	// Verify scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 scan to be enqueued, got %d", len(mockQueue.enqueuedScans))
	}

	enqueuedScan := mockQueue.enqueuedScans[0]
	if enqueuedScan.Image.Digest != "sha256:abc123" {
		t.Errorf("Expected digest sha256:abc123, got %s", enqueuedScan.Image.Digest)
	}
	if enqueuedScan.NodeName != "worker-1" {
		t.Errorf("Expected node worker-1, got %s", enqueuedScan.NodeName)
	}
	if enqueuedScan.ContainerRuntime != "containerd" {
		t.Errorf("Expected runtime containerd, got %s", enqueuedScan.ContainerRuntime)
	}
}

func TestManagerDoesNotEnqueueDuplicateScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_dup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first instance
	instance1 := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod-1",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:same",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainerInstance(instance1)
	time.Sleep(100 * time.Millisecond)

	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 scan after first instance, got %d", len(mockQueue.enqueuedScans))
	}

	// Mark the scan as completed
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:same", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Add second instance with same image (should not trigger new scan)
	instance2 := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod-2",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:same",
		},
		NodeName:         "worker-2",
		ContainerRuntime: "docker",
	}

	manager.AddContainerInstance(instance2)
	time.Sleep(100 * time.Millisecond)

	// Should still be only 1 enqueued scan
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected 1 scan total (no duplicate), got %d", len(mockQueue.enqueuedScans))
	}
}

func TestManagerSetInstancesEnqueuesMultipleScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_set_multi_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Set multiple instances with different images
	instances := []containers.ContainerInstance{
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-1",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:image1",
			},
			NodeName:         "worker-1",
			ContainerRuntime: "containerd",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-2",
				Container: "envoy",
			},
			Image: containers.ImageID{
				Repository: "envoy",
				Tag:        "v1.20",
				Digest:     "sha256:image2",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "kube-system",
				Pod:       "pod-3",
				Container: "coredns",
			},
			Image: containers.ImageID{
				Repository: "coredns",
				Tag:        "v1.9",
				Digest:     "sha256:image3",
			},
			NodeName:         "worker-3",
			ContainerRuntime: "containerd",
		},
	}

	manager.SetContainerInstances(instances)
	time.Sleep(100 * time.Millisecond)

	// Should have enqueued 3 scans
	if len(mockQueue.enqueuedScans) != 3 {
		t.Errorf("Expected 3 scans to be enqueued, got %d", len(mockQueue.enqueuedScans))
	}

	// Verify all unique digests were enqueued
	digests := make(map[string]bool)
	for _, scan := range mockQueue.enqueuedScans {
		digests[scan.Image.Digest] = true
	}

	if len(digests) != 3 {
		t.Errorf("Expected 3 unique digests, got %d", len(digests))
	}
}

func TestManagerSetInstancesDeduplicatesScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_set_dedup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Set multiple instances with same image (should only enqueue once)
	instances := []containers.ContainerInstance{
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-1",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:shared",
			},
			NodeName:         "worker-1",
			ContainerRuntime: "containerd",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-2",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:shared",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "kube-system",
				Pod:       "pod-3",
				Container: "nginx",
			},
			Image: containers.ImageID{
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:shared",
			},
			NodeName:         "worker-3",
			ContainerRuntime: "containerd",
		},
	}

	manager.SetContainerInstances(instances)
	time.Sleep(100 * time.Millisecond)

	// Should only enqueue 1 scan (deduplicated)
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected 1 scan (deduplicated), got %d", len(mockQueue.enqueuedScans))
	}

	if mockQueue.enqueuedScans[0].Image.Digest != "sha256:shared" {
		t.Errorf("Expected digest sha256:shared, got %s", mockQueue.enqueuedScans[0].Image.Digest)
	}
}

func TestManagerRemoveInstance(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_remove_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database
	manager := containers.NewManager()
	manager.SetDatabase(db)

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

	manager.AddContainerInstance(instance)

	// Verify instance exists
	if manager.GetInstanceCount() != 1 {
		t.Fatalf("Expected 1 instance, got %d", manager.GetInstanceCount())
	}

	// Remove instance
	manager.RemoveContainerInstance(instance.ID)

	// Verify instance is removed from manager
	if manager.GetInstanceCount() != 0 {
		t.Errorf("Expected 0 instances in manager after removal, got %d", manager.GetInstanceCount())
	}

	// Verify instance is removed from database
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get instances from database: %v", err)
	}

	instanceRows := allInstances.([]database.ContainerInstanceRow)
	if len(instanceRows) != 0 {
		t.Errorf("Expected 0 instances in database after removal, got %d", len(instanceRows))
	}
}

func TestManagerWithoutDatabase(t *testing.T) {
	// Create manager without database
	manager := containers.NewManager()

	// Add instance (should work without database)
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

	manager.AddContainerInstance(instance)

	// Verify instance is in manager
	if manager.GetInstanceCount() != 1 {
		t.Errorf("Expected 1 instance in manager, got %d", manager.GetInstanceCount())
	}

	// This should work fine without database
	retrieved, exists := manager.GetInstance("default", "test-pod", "nginx")
	if !exists {
		t.Error("Instance not found in manager")
	}
	if retrieved.Image.Digest != "sha256:abc123" {
		t.Errorf("Retrieved instance has wrong digest: %s", retrieved.Image.Digest)
	}
}

func TestManagerWithoutScanQueue(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database but no scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	// Add instance (should work without scan queue)
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

	manager.AddContainerInstance(instance)

	// Verify instance is in manager
	if manager.GetInstanceCount() != 1 {
		t.Errorf("Expected 1 instance in manager, got %d", manager.GetInstanceCount())
	}

	// Verify instance is in database
	allInstances, err := db.GetAllInstances()
	if err != nil {
		t.Fatalf("Failed to get instances from database: %v", err)
	}

	instanceRows := allInstances.([]database.ContainerInstanceRow)
	if len(instanceRows) != 1 {
		t.Errorf("Expected 1 instance in database, got %d", len(instanceRows))
	}
}

func TestManagerRetryFailedScan(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_retry_failed_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first instance (should enqueue normal scan)
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:failed",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Mark the scan as failed
	err = db.UpdateScanStatus("sha256:failed", "failed", "test error")
	if err != nil {
		t.Fatalf("Failed to update scan status: %v", err)
	}

	// Add same instance again (should enqueue force scan)
	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify force scan was enqueued
	if len(mockQueue.enqueuedForceScans) != 1 {
		t.Errorf("Expected 1 force scan for failed image, got %d", len(mockQueue.enqueuedForceScans))
	}
	if mockQueue.enqueuedForceScans[0].Image.Digest != "sha256:failed" {
		t.Errorf("Expected digest sha256:failed, got %s", mockQueue.enqueuedForceScans[0].Image.Digest)
	}
}

func TestManagerRetryIncompleteData(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_retry_incomplete_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:incomplete",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Store SBOM but mark as scanned (simulating incomplete data - missing vulnerabilities)
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:incomplete", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Verify data is incomplete
	isComplete, err := db.IsScanDataComplete("sha256:incomplete")
	if err != nil {
		t.Fatalf("Failed to check data completeness: %v", err)
	}
	if isComplete {
		t.Fatal("Expected data to be incomplete (missing vulnerabilities)")
	}

	// Add same instance again (should enqueue force scan because data is incomplete)
	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify force scan was enqueued
	if len(mockQueue.enqueuedForceScans) != 1 {
		t.Errorf("Expected 1 force scan for incomplete data, got %d", len(mockQueue.enqueuedForceScans))
	}
	if mockQueue.enqueuedForceScans[0].Image.Digest != "sha256:incomplete" {
		t.Errorf("Expected digest sha256:incomplete, got %s", mockQueue.enqueuedForceScans[0].Image.Digest)
	}
}

func TestManagerNoRetryForCompleteData(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_retry_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:complete",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Store complete data (SBOM and vulnerabilities)
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:complete", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	vulnJSON := []byte(`{"vulnerabilities":[]}`)
	err = db.StoreVulnerabilities("sha256:complete", vulnJSON, time.Time{})
	if err != nil {
		t.Fatalf("Failed to store vulnerabilities: %v", err)
	}

	// Verify data is complete
	isComplete, err := db.IsScanDataComplete("sha256:complete")
	if err != nil {
		t.Fatalf("Failed to check data completeness: %v", err)
	}
	if !isComplete {
		t.Fatal("Expected data to be complete")
	}

	// Add same instance again (should NOT enqueue any scan - data is complete)
	manager.AddContainerInstance(instance)
	time.Sleep(100 * time.Millisecond)

	// Verify no additional scans were enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected still 1 normal scan (no retry), got %d", len(mockQueue.enqueuedScans))
	}
	if len(mockQueue.enqueuedForceScans) != 0 {
		t.Errorf("Expected 0 force scans for complete data, got %d", len(mockQueue.enqueuedForceScans))
	}
}
