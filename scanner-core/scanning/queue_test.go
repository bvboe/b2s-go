package scanning

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	// Note: SQLite driver is imported via Grype's dependencies
	// DO NOT import sqlitedriver here to avoid duplicate registration
)

// TestJobQueueIntegration tests the complete scanning workflow
func TestJobQueueIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Track which images were scanned
	scannedImages := make(map[string]bool)
	retrieverCalled := make(chan containers.ImageID, 10)

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCalled <- image
		scannedImages[image.Digest] = true
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Repository: "nginx",
		Tag:        "1.21",
		Digest:     "sha256:abc123",
	}

	// Create a container instance to initialize the image record in the database
	testInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the instance to the database (this creates the image record with status='pending')
	_, err = db.AddInstance(testInstance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Enqueue a scan job
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}

	queue.Enqueue(job)

	// Wait for the job to be processed
	select {
	case scannedImage := <-retrieverCalled:
		if scannedImage.Digest != testImage.Digest {
			t.Errorf("Expected digest %s, got %s", testImage.Digest, scannedImage.Digest)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for SBOM retriever to be called")
	}

	// Give the worker time to update the database
	time.Sleep(100 * time.Millisecond)

	// Verify the SBOM was stored
	sbom, err := db.GetSBOM(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get SBOM: %v", err)
	}
	if len(sbom) == 0 {
		t.Error("SBOM was not stored")
	}

	// Verify scan status
	status, err := db.GetImageScanStatus(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "scanned" {
		t.Errorf("Expected status 'scanned', got '%s'", status)
	}
}

// TestJobQueueErrorHandling tests error scenarios
func TestJobQueueErrorHandling(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_queue_error_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Mock SBOM retriever that fails
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return nil, errors.New("scan failed: image not found")
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Repository: "nginx",
		Tag:        "1.21",
		Digest:     "sha256:def456",
	}

	// Create a container instance to initialize the image record
	testInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the instance to the database
	_, err = db.AddInstance(testInstance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Enqueue a scan job
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}

	queue.Enqueue(job)

	// Wait for the job to be processed
	time.Sleep(1 * time.Second)

	// Verify scan status is 'failed'
	status, err := db.GetImageScanStatus(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", status)
	}

	// Verify SBOM is not available (GetSBOM should return an error)
	sbom, err := db.GetSBOM(testImage.Digest)
	if err == nil {
		t.Error("Expected error when retrieving SBOM for failed scan")
	}
	if sbom != nil {
		t.Error("SBOM should be nil for failed scan")
	}
}

// TestJobQueueSkipAlreadyScanned tests that already-scanned images are skipped
func TestJobQueueSkipAlreadyScanned(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_queue_skip_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var retrieverCallCount atomic.Int32

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCallCount.Add(1)
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Repository: "nginx",
		Tag:        "1.21",
		Digest:     "sha256:ghi789",
	}

	// Create a container instance to initialize the image record
	testInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the instance to the database
	_, err = db.AddInstance(testInstance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// First scan
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}
	queue.Enqueue(job)

	// Wait for first scan to complete
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to be called once, got %d", retrieverCallCount.Load())
	}

	// Second scan of the same image (should be skipped)
	queue.Enqueue(job)

	// Wait to see if second scan happens
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to still be called once, got %d", retrieverCallCount.Load())
	}
}

// TestJobQueueForceScan tests that ForceScan bypasses the already-scanned check
func TestJobQueueForceScan(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_queue_force_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var retrieverCallCount atomic.Int32

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCallCount.Add(1)
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Repository: "nginx",
		Tag:        "1.21",
		Digest:     "sha256:jkl012",
	}

	// Create a container instance to initialize the image record
	testInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the instance to the database
	_, err = db.AddInstance(testInstance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// First scan
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}
	queue.Enqueue(job)

	// Wait for first scan to complete
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to be called once, got %d", retrieverCallCount.Load())
	}

	// Force rescan of the same image
	job.ForceScan = true
	queue.Enqueue(job)

	// Wait for rescan to complete
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 2 {
		t.Errorf("Expected retriever to be called twice (force scan), got %d", retrieverCallCount.Load())
	}
}
