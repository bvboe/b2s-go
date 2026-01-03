package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

func TestGetScannedContainerInstances(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_get_scanned_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add instance with completed scan
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

	// Store SBOM and complete the scan
	err = db.StoreSBOM("sha256:abc123", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Get image ID and parse SBOM data (sets OS info)
	imageID, _, err := db.GetOrCreateImage(instance.Image)
	if err != nil {
		t.Fatalf("Failed to get image ID: %v", err)
	}

	err = db.ParseAndStoreImageData(imageID)
	if err != nil {
		t.Fatalf("Failed to parse image data: %v", err)
	}

	err = db.UpdateStatus("sha256:abc123", StatusCompleted, "")
	if err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	// Get scanned instances
	instances, err := db.GetScannedContainerInstances()
	if err != nil {
		t.Fatalf("Failed to get scanned instances: %v", err)
	}

	// Verify results
	if len(instances) != 1 {
		t.Errorf("Expected 1 instance, got %d", len(instances))
	}

	if len(instances) > 0 {
		inst := instances[0]
		if inst.Namespace != "default" {
			t.Errorf("Expected namespace=default, got %s", inst.Namespace)
		}
		if inst.Pod != "test-pod" {
			t.Errorf("Expected pod=test-pod, got %s", inst.Pod)
		}
		if inst.Container != "nginx" {
			t.Errorf("Expected container=nginx, got %s", inst.Container)
		}
		if inst.NodeName != "worker-1" {
			t.Errorf("Expected node_name=worker-1, got %s", inst.NodeName)
		}
		if inst.Repository != "nginx" {
			t.Errorf("Expected repository=nginx, got %s", inst.Repository)
		}
		if inst.Tag != "1.21" {
			t.Errorf("Expected tag=1.21, got %s", inst.Tag)
		}
		if inst.Digest != "sha256:abc123" {
			t.Errorf("Expected digest=sha256:abc123, got %s", inst.Digest)
		}
	}
}

func TestGetScannedContainerInstances_OnlyCompleted(t *testing.T) {
	dbPath := "/tmp/test_scanned_completed_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add completed instance
	completedInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "completed-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:completed",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(completedInstance)
	if err != nil {
		t.Fatalf("Failed to add completed instance: %v", err)
	}

	err = db.StoreSBOM("sha256:completed", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	err = db.UpdateStatus("sha256:completed", StatusCompleted, "")
	if err != nil {
		t.Fatalf("Failed to update completed status: %v", err)
	}

	// Add pending instance
	pendingInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "pending-pod",
			Container: "redis",
		},
		Image: containers.ImageID{
			Repository: "redis",
			Tag:        "latest",
			Digest:     "sha256:pending",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(pendingInstance)
	if err != nil {
		t.Fatalf("Failed to add pending instance: %v", err)
	}

	// Get scanned instances - should only return completed
	instances, err := db.GetScannedContainerInstances()
	if err != nil {
		t.Fatalf("Failed to get scanned instances: %v", err)
	}

	if len(instances) != 1 {
		t.Errorf("Expected 1 instance (only completed), got %d", len(instances))
	}

	if len(instances) > 0 && instances[0].Pod != "completed-pod" {
		t.Errorf("Expected completed-pod, got %s", instances[0].Pod)
	}
}

func TestGetVulnerabilityInstances(t *testing.T) {
	dbPath := "/tmp/test_vuln_instances_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "kube-system",
			Pod:       "nginx-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:vuln-test",
		},
		NodeName:         "worker-2",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Store SBOM and complete scan
	err = db.StoreSBOM("sha256:vuln-test", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	err = db.UpdateStatus("sha256:vuln-test", StatusCompleted, "")
	if err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	// Get image ID to add vulnerabilities
	imageID, _, err := db.GetOrCreateImage(instance.Image)
	if err != nil {
		t.Fatalf("Failed to get image ID: %v", err)
	}

	// Insert vulnerabilities directly (simulating what StoreVulnerabilities would do)
	_, err = db.conn.Exec(`
		INSERT INTO vulnerabilities (image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, imageID, "CVE-2022-1234", "busybox", "1.35.0", "apk", "Critical", "fixed", "1.35.1", 1)
	if err != nil {
		t.Fatalf("Failed to insert vulnerability 1: %v", err)
	}

	_, err = db.conn.Exec(`
		INSERT INTO vulnerabilities (image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, imageID, "CVE-2023-5678", "openssl", "1.1.1", "deb", "High", "not-fixed", "", 2)
	if err != nil {
		t.Fatalf("Failed to insert vulnerability 2: %v", err)
	}

	// Get vulnerability instances
	vulnInstances, err := db.GetVulnerabilityInstances()
	if err != nil {
		t.Fatalf("Failed to get vulnerability instances: %v", err)
	}

	// Verify results
	if len(vulnInstances) != 2 {
		t.Fatalf("Expected 2 vulnerability instances, got %d", len(vulnInstances))
	}

	// Check first vulnerability
	vuln1 := vulnInstances[0]
	if vuln1.Namespace != "kube-system" {
		t.Errorf("Expected namespace=kube-system, got %s", vuln1.Namespace)
	}
	if vuln1.Pod != "nginx-pod" {
		t.Errorf("Expected pod=nginx-pod, got %s", vuln1.Pod)
	}
	if vuln1.Container != "nginx" {
		t.Errorf("Expected container=nginx, got %s", vuln1.Container)
	}
	if vuln1.NodeName != "worker-2" {
		t.Errorf("Expected node_name=worker-2, got %s", vuln1.NodeName)
	}
	if vuln1.CVEID != "CVE-2022-1234" {
		t.Errorf("Expected CVE-2022-1234, got %s", vuln1.CVEID)
	}
	if vuln1.PackageName != "busybox" {
		t.Errorf("Expected package_name=busybox, got %s", vuln1.PackageName)
	}
	if vuln1.Severity != "Critical" {
		t.Errorf("Expected severity=Critical, got %s", vuln1.Severity)
	}
	if vuln1.FixStatus != "fixed" {
		t.Errorf("Expected fix_status=fixed, got %s", vuln1.FixStatus)
	}
	if vuln1.Count != 1 {
		t.Errorf("Expected count=1, got %d", vuln1.Count)
	}

	// Check second vulnerability
	vuln2 := vulnInstances[1]
	if vuln2.CVEID != "CVE-2023-5678" {
		t.Errorf("Expected CVE-2023-5678, got %s", vuln2.CVEID)
	}
	if vuln2.Severity != "High" {
		t.Errorf("Expected severity=High, got %s", vuln2.Severity)
	}
	if vuln2.Count != 2 {
		t.Errorf("Expected count=2, got %d", vuln2.Count)
	}
}

func TestGetVulnerabilityInstances_EmptyResult(t *testing.T) {
	dbPath := "/tmp/test_vuln_empty_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add instance without vulnerabilities
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "alpine-pod",
			Container: "alpine",
		},
		Image: containers.ImageID{
			Repository: "alpine",
			Tag:        "3.19",
			Digest:     "sha256:no-vulns",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	err = db.StoreSBOM("sha256:no-vulns", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	err = db.UpdateStatus("sha256:no-vulns", StatusCompleted, "")
	if err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	// Get vulnerability instances - should be empty
	vulnInstances, err := db.GetVulnerabilityInstances()
	if err != nil {
		t.Fatalf("Failed to get vulnerability instances: %v", err)
	}

	if len(vulnInstances) != 0 {
		t.Errorf("Expected 0 vulnerability instances, got %d", len(vulnInstances))
	}
}

func TestGetVulnerabilityInstances_OnlyCompletedScans(t *testing.T) {
	dbPath := "/tmp/test_vuln_completed_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add completed instance with vulnerability
	completedInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "completed-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:completed",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(completedInstance)
	if err != nil {
		t.Fatalf("Failed to add completed instance: %v", err)
	}

	err = db.StoreSBOM("sha256:completed", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	err = db.UpdateStatus("sha256:completed", StatusCompleted, "")
	if err != nil {
		t.Fatalf("Failed to update completed status: %v", err)
	}

	completedImageID, _, err := db.GetOrCreateImage(completedInstance.Image)
	if err != nil {
		t.Fatalf("Failed to get completed image ID: %v", err)
	}

	_, err = db.conn.Exec(`
		INSERT INTO vulnerabilities (image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, completedImageID, "CVE-2024-COMPLETED", "pkg1", "1.0", "apk", "High", "fixed", "1.1", 1)
	if err != nil {
		t.Fatalf("Failed to insert vulnerability for completed: %v", err)
	}

	// Add failed instance with vulnerability
	failedInstance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "failed-pod",
			Container: "redis",
		},
		Image: containers.ImageID{
			Repository: "redis",
			Tag:        "latest",
			Digest:     "sha256:failed",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(failedInstance)
	if err != nil {
		t.Fatalf("Failed to add failed instance: %v", err)
	}

	err = db.UpdateStatus("sha256:failed", StatusVulnScanFailed, "scan error")
	if err != nil {
		t.Fatalf("Failed to update failed status: %v", err)
	}

	failedImageID, _, err := db.GetOrCreateImage(failedInstance.Image)
	if err != nil {
		t.Fatalf("Failed to get failed image ID: %v", err)
	}

	_, err = db.conn.Exec(`
		INSERT INTO vulnerabilities (image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, failedImageID, "CVE-2024-FAILED", "pkg2", "2.0", "apk", "Critical", "fixed", "2.1", 1)
	if err != nil {
		t.Fatalf("Failed to insert vulnerability for failed: %v", err)
	}

	// Get vulnerability instances - should only return completed
	vulnInstances, err := db.GetVulnerabilityInstances()
	if err != nil {
		t.Fatalf("Failed to get vulnerability instances: %v", err)
	}

	if len(vulnInstances) != 1 {
		t.Errorf("Expected 1 vulnerability instance (only completed), got %d", len(vulnInstances))
	}

	if len(vulnInstances) > 0 {
		if vulnInstances[0].CVEID != "CVE-2024-COMPLETED" {
			t.Errorf("Expected CVE-2024-COMPLETED, got %s", vulnInstances[0].CVEID)
		}
		if vulnInstances[0].Pod != "completed-pod" {
			t.Errorf("Expected completed-pod, got %s", vulnInstances[0].Pod)
		}
	}
}

func TestGetLastUpdatedTimestamp(t *testing.T) {
	dbPath := "/tmp/test_last_updated_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Initially should return empty string when no images exist
	timestamp, err := db.GetLastUpdatedTimestamp("images")
	if err != nil {
		t.Fatalf("Failed to get last updated timestamp: %v", err)
	}
	if timestamp != "" {
		t.Errorf("Expected empty timestamp, got %s", timestamp)
	}

	// Add an image
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:timestamp-test",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Store SBOM (this updates the image's updated_at timestamp)
	err = db.StoreSBOM("sha256:timestamp-test", []byte(`{"test":"sbom"}`))
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Now should return a timestamp
	timestamp, err = db.GetLastUpdatedTimestamp("images")
	if err != nil {
		t.Fatalf("Failed to get last updated timestamp: %v", err)
	}
	if timestamp == "" {
		t.Error("Expected non-empty timestamp after updating image")
	}
}
