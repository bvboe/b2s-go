package jobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
)

var (
	errNotFound = fmt.Errorf("not found")
	errDatabase = fmt.Errorf("database error")
)

// Mock implementations for testing

type MockDatabaseUpdater struct {
	hasChanged bool
	err        error
}

func (m *MockDatabaseUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	return m.hasChanged, m.err
}

type MockDatabase struct {
	images    []database.ContainerImage
	instances map[string]*database.ContainerInstanceRow
	err       error
}

func (m *MockDatabase) GetImagesByStatus(status database.Status) ([]database.ContainerImage, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.images, nil
}

func (m *MockDatabase) GetFirstInstanceForImage(digest string) (*database.ContainerInstanceRow, error) {
	if m.err != nil {
		return nil, m.err
	}
	if instance, ok := m.instances[digest]; ok {
		return instance, nil
	}
	return nil, errNotFound
}

type MockScanQueue struct {
	enqueuedScans []EnqueuedScan
}

type EnqueuedScan struct {
	Digest           string
	Repository       string
	Tag              string
	NodeName         string
	ContainerRuntime string
}

func (m *MockScanQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedScans = append(m.enqueuedScans, EnqueuedScan{
		Digest:           image.Digest,
		Repository:       image.Repository,
		Tag:              image.Tag,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

// Test: database has changed, rescans triggered
func TestRescanDatabaseJob_Integration(t *testing.T) {
	// Setup: mock database updater that returns "changed"
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: true}

	// Setup: mock database with completed images
	mockDB := &MockDatabase{
		images: []database.ContainerImage{
			{
				ID:     1,
				Digest: "sha256:abc123",
				Status: "completed",
			},
			{
				ID:     2,
				Digest: "sha256:def456",
				Status: "completed",
			},
		},
		instances: map[string]*database.ContainerInstanceRow{
			"sha256:abc123": {
				Namespace:        "default",
				Pod:              "pod1",
				Container:        "container1",
				Repository:       "nginx",
				Tag:              "latest",
				NodeName:         "node1",
				ContainerRuntime: "docker",
			},
			"sha256:def456": {
				Namespace:        "default",
				Pod:              "pod2",
				Container:        "container2",
				Repository:       "redis",
				Tag:              "7.0",
				NodeName:         "node2",
				ContainerRuntime: "containerd",
			},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: 2 images were enqueued
	if len(mockQueue.enqueuedScans) != 2 {
		t.Errorf("Expected 2 rescans, got %d", len(mockQueue.enqueuedScans))
	}

	// Verify: correct images enqueued
	expectedScans := map[string]EnqueuedScan{
		"sha256:abc123": {
			Digest:           "sha256:abc123",
			Repository:       "nginx",
			Tag:              "latest",
			NodeName:         "node1",
			ContainerRuntime: "docker",
		},
		"sha256:def456": {
			Digest:           "sha256:def456",
			Repository:       "redis",
			Tag:              "7.0",
			NodeName:         "node2",
			ContainerRuntime: "containerd",
		},
	}

	for _, scan := range mockQueue.enqueuedScans {
		expected, ok := expectedScans[scan.Digest]
		if !ok {
			t.Errorf("Unexpected digest enqueued: %s", scan.Digest)
			continue
		}

		if scan.Repository != expected.Repository {
			t.Errorf("Expected repository %s, got %s", expected.Repository, scan.Repository)
		}
		if scan.Tag != expected.Tag {
			t.Errorf("Expected tag %s, got %s", expected.Tag, scan.Tag)
		}
		if scan.NodeName != expected.NodeName {
			t.Errorf("Expected node %s, got %s", expected.NodeName, scan.NodeName)
		}
		if scan.ContainerRuntime != expected.ContainerRuntime {
			t.Errorf("Expected runtime %s, got %s", expected.ContainerRuntime, scan.ContainerRuntime)
		}
	}
}

// Test: no changes detected, no rescans triggered
func TestRescanDatabaseJob_NoChanges(t *testing.T) {
	// Setup: mock database updater that returns "no change"
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: false}

	// Setup: mock database with completed images
	mockDB := &MockDatabase{
		images: []database.ContainerImage{
			{ID: 1, Digest: "sha256:abc123", Status: "completed"},
		},
		instances: map[string]*database.ContainerInstanceRow{
			"sha256:abc123": {NodeName: "node1", ContainerRuntime: "docker", Repository: "nginx", Tag: "latest"},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: no completed images, job succeeds with no work
func TestRescanDatabaseJob_NoCompletedImages(t *testing.T) {
	// Setup: mock database updater that returns "changed"
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: true}

	// Setup: mock database with NO completed images
	mockDB := &MockDatabase{
		images:    []database.ContainerImage{}, // Empty
		instances: map[string]*database.ContainerInstanceRow{},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job should succeed with no images, got error: %v", err)
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: missing container instances, orphaned images skipped
func TestRescanDatabaseJob_MissingInstances(t *testing.T) {
	// Setup: mock database updater that returns "changed"
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: true}

	// Setup: mock database with completed images but missing instances
	mockDB := &MockDatabase{
		images: []database.ContainerImage{
			{ID: 1, Digest: "sha256:abc123", Status: "completed"},
			{ID: 2, Digest: "sha256:def456", Status: "completed"}, // No instance
			{ID: 3, Digest: "sha256:ghi789", Status: "completed"},
		},
		instances: map[string]*database.ContainerInstanceRow{
			"sha256:abc123": {NodeName: "node1", ContainerRuntime: "docker", Repository: "nginx", Tag: "latest"},
			// sha256:def456 is missing (orphaned)
			"sha256:ghi789": {NodeName: "node3", ContainerRuntime: "containerd", Repository: "redis", Tag: "7.0"},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: only 2 rescans enqueued (orphaned image skipped)
	if len(mockQueue.enqueuedScans) != 2 {
		t.Errorf("Expected 2 rescans (orphaned skipped), got %d", len(mockQueue.enqueuedScans))
	}

	// Verify: orphaned digest NOT enqueued
	for _, scan := range mockQueue.enqueuedScans {
		if scan.Digest == "sha256:def456" {
			t.Error("Orphaned image should not be enqueued")
		}
	}
}

// Test: database updater error, job fails
func TestRescanDatabaseJob_UpdaterError(t *testing.T) {
	// Setup: mock database updater that returns error
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: false,
		err:        errDatabase,
	}

	mockDB := &MockDatabase{
		images:    []database.ContainerImage{},
		instances: map[string]*database.ContainerInstanceRow{},
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err == nil {
		t.Error("Expected error from database updater")
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans on error, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: database error when getting images
func TestRescanDatabaseJob_DatabaseError(t *testing.T) {
	// Setup: mock database updater that returns "changed"
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: true}

	// Setup: mock database that returns error
	mockDB := &MockDatabase{
		images:    nil,
		instances: nil,
		err:       errDatabase,
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err == nil {
		t.Error("Expected error from database")
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans on error, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: context cancellation during job execution
func TestRescanDatabaseJob_ContextCancellation(t *testing.T) {
	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Setup: mock database updater (will be called with cancelled context)
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: false}

	mockDB := &MockDatabase{
		images:    []database.ContainerImage{},
		instances: map[string]*database.ContainerInstanceRow{},
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job with cancelled context
	// Note: Our current implementation doesn't explicitly check context in CheckForUpdates,
	// but the database updater's HTTP client will respect the context
	err := job.Run(ctx)

	// The database updater should handle context cancellation
	// For this test, we just verify the job doesn't panic
	_ = err // Error handling depends on database updater implementation
}

// Test: job name
func TestRescanDatabaseJob_Name(t *testing.T) {
	mockDBUpdater := &MockDatabaseUpdater{}
	mockDB := &MockDatabase{}
	mockQueue := &MockScanQueue{}

	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	if job.Name() != "rescan-database" {
		t.Errorf("Expected name 'rescan-database', got '%s'", job.Name())
	}
}

// Test: panic on nil dependencies
func TestNewRescanDatabaseJob_NilDependencies(t *testing.T) {
	mockDBUpdater := &MockDatabaseUpdater{}
	mockDB := &MockDatabase{}
	mockQueue := &MockScanQueue{}

	// Test nil database updater
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil dbUpdater")
		}
	}()
	NewRescanDatabaseJob(nil, mockDB, mockQueue)

	// Test nil database
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil database")
		}
	}()
	NewRescanDatabaseJob(mockDBUpdater, nil, mockQueue)

	// Test nil scan queue
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil scan queue")
		}
	}()
	NewRescanDatabaseJob(mockDBUpdater, mockDB, nil)
}
