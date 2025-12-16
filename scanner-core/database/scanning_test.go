package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

func TestGetImageScanStatus(t *testing.T) {
	dbPath := "/tmp/test_scan_status_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add an instance to create an image with pending status
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

	// Check scan status (should be pending)
	status, err := db.GetImageScanStatus("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "pending" {
		t.Errorf("Expected status 'pending', got '%s'", status)
	}
}

func TestGetImageScanStatusNonExistent(t *testing.T) {
	dbPath := "/tmp/test_scan_status_nonexist_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Check status for non-existent image (should return "pending")
	status, err := db.GetImageScanStatus("sha256:nonexistent")
	if err != nil {
		t.Fatalf("Expected no error for non-existent image, got: %v", err)
	}
	if status != "pending" {
		t.Errorf("Expected 'pending' for non-existent image, got '%s'", status)
	}
}

func TestUpdateScanStatus(t *testing.T) {
	dbPath := "/tmp/test_update_status_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add an instance to create an image
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

	// Update status to scanning
	err = db.UpdateScanStatus("sha256:abc123", "scanning", "")
	if err != nil {
		t.Fatalf("Failed to update scan status: %v", err)
	}

	// Verify status was updated
	status, err := db.GetImageScanStatus("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "scanning" {
		t.Errorf("Expected status 'scanning', got '%s'", status)
	}

	// Update status to failed with error
	err = db.UpdateScanStatus("sha256:abc123", "failed", "scan failed: timeout")
	if err != nil {
		t.Fatalf("Failed to update scan status to failed: %v", err)
	}

	// Verify status was updated
	status, err = db.GetImageScanStatus("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", status)
	}
}

func TestStoreSBOM(t *testing.T) {
	dbPath := "/tmp/test_store_sbom_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add an instance to create an image
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

	// Store SBOM
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:abc123", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Verify SBOM was stored
	retrieved, err := db.GetSBOM("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get SBOM: %v", err)
	}
	if string(retrieved) != string(sbomJSON) {
		t.Errorf("Retrieved SBOM doesn't match. Expected %s, got %s", string(sbomJSON), string(retrieved))
	}

	// Verify status was set to scanned
	status, err := db.GetImageScanStatus("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "scanned" {
		t.Errorf("Expected status 'scanned', got '%s'", status)
	}
}

func TestGetSBOM(t *testing.T) {
	dbPath := "/tmp/test_get_sbom_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add an instance to create an image
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

	// Try to get SBOM before it's stored (should return error)
	_, err = db.GetSBOM("sha256:abc123")
	if err == nil {
		t.Error("Expected error when getting SBOM before it's stored")
	}

	// Store SBOM
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:abc123", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Now get SBOM should succeed
	retrieved, err := db.GetSBOM("sha256:abc123")
	if err != nil {
		t.Fatalf("Failed to get SBOM: %v", err)
	}
	if string(retrieved) != string(sbomJSON) {
		t.Errorf("Retrieved SBOM doesn't match")
	}
}

func TestGetSBOMNonExistent(t *testing.T) {
	dbPath := "/tmp/test_get_sbom_nonexist_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Try to get SBOM for non-existent image
	_, err = db.GetSBOM("sha256:nonexistent")
	if err == nil {
		t.Error("Expected error when getting SBOM for non-existent image")
	}
}

func TestGetImagesByScanStatus(t *testing.T) {
	dbPath := "/tmp/test_images_by_status_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add multiple instances with different images
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
				Digest:     "sha256:pending1",
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
				Tag:        "1.22",
				Digest:     "sha256:pending2",
			},
			NodeName:         "worker-1",
			ContainerRuntime: "containerd",
		},
		{
			ID: containers.ContainerInstanceID{
				Namespace: "default",
				Pod:       "pod-3",
				Container: "envoy",
			},
			Image: containers.ImageID{
				Repository: "envoy",
				Tag:        "v1.20",
				Digest:     "sha256:scanned1",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
	}

	for _, instance := range instances {
		_, err := db.AddInstance(instance)
		if err != nil {
			t.Fatalf("Failed to add instance: %v", err)
		}
	}

	// Mark one image as scanned
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:scanned1", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Get pending images
	pendingImages, err := db.GetImagesByScanStatus("pending")
	if err != nil {
		t.Fatalf("Failed to get pending images: %v", err)
	}
	if len(pendingImages) != 2 {
		t.Errorf("Expected 2 pending images, got %d", len(pendingImages))
	}

	// Get scanned images
	scannedImages, err := db.GetImagesByScanStatus("scanned")
	if err != nil {
		t.Fatalf("Failed to get scanned images: %v", err)
	}
	if len(scannedImages) != 1 {
		t.Errorf("Expected 1 scanned image, got %d", len(scannedImages))
	}
	if scannedImages[0].Digest != "sha256:scanned1" {
		t.Errorf("Expected scanned1, got %s", scannedImages[0].Digest)
	}
}

func TestGetFirstInstanceForImage(t *testing.T) {
	dbPath := "/tmp/test_first_instance_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add multiple instances with the same image on different nodes
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
	}

	for _, instance := range instances {
		_, err := db.AddInstance(instance)
		if err != nil {
			t.Fatalf("Failed to add instance: %v", err)
		}
	}

	// Get first instance for the image
	firstInstance, err := db.GetFirstInstanceForImage("sha256:shared")
	if err != nil {
		t.Fatalf("Failed to get first instance: %v", err)
	}
	if firstInstance == nil {
		t.Fatal("Expected first instance to be non-nil")
	}

	// Verify it's one of the instances we added
	if firstInstance.NodeName != "worker-1" && firstInstance.NodeName != "worker-2" {
		t.Errorf("Expected node to be worker-1 or worker-2, got %s", firstInstance.NodeName)
	}
}

func TestGetFirstInstanceForImageNonExistent(t *testing.T) {
	dbPath := "/tmp/test_first_instance_nonexist_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Try to get first instance for non-existent image
	instance, err := db.GetFirstInstanceForImage("sha256:nonexistent")
	if err == nil {
		t.Error("Expected error when getting first instance for non-existent image")
	}
	if instance != nil {
		t.Error("Expected nil instance for non-existent image")
	}
}

func TestScanWorkflow(t *testing.T) {
	dbPath := "/tmp/test_scan_workflow_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Simulate complete scan workflow
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:workflow123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	// 1. Add instance (image starts as pending)
	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	status, _ := db.GetImageScanStatus("sha256:workflow123")
	if status != "pending" {
		t.Errorf("Initial status should be pending, got %s", status)
	}

	// 2. Start scanning (mark as scanning)
	err = db.UpdateScanStatus("sha256:workflow123", "scanning", "")
	if err != nil {
		t.Fatalf("Failed to update to scanning: %v", err)
	}

	status, _ = db.GetImageScanStatus("sha256:workflow123")
	if status != "scanning" {
		t.Errorf("Status should be scanning, got %s", status)
	}

	// 3. Complete scan (store SBOM, marks as scanned)
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:workflow123", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	status, _ = db.GetImageScanStatus("sha256:workflow123")
	if status != "scanned" {
		t.Errorf("Final status should be scanned, got %s", status)
	}

	// Verify SBOM is retrievable
	retrieved, err := db.GetSBOM("sha256:workflow123")
	if err != nil {
		t.Fatalf("Failed to get SBOM: %v", err)
	}
	if string(retrieved) != string(sbomJSON) {
		t.Error("Retrieved SBOM doesn't match stored SBOM")
	}
}
