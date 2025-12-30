package metrics

import (
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	_ "modernc.org/sqlite" // SQLite driver
)

// MockInfoProvider implements InfoProvider for testing
type MockInfoProvider struct {
	clusterName string
	version     string
}

func (m *MockInfoProvider) GetClusterName() string {
	return m.clusterName
}

func (m *MockInfoProvider) GetVersion() string {
	return m.version
}

func TestCollector_Collect(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Add test data
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "test-namespace",
			Pod:       "test-pod",
			Container: "test-container",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "latest",
			Digest:     "sha256:abc123",
		},
		NodeName:         "test-node",
		ContainerRuntime: "docker",
	}

	_, err = db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Create collector
	infoProvider := &MockInfoProvider{
		clusterName: "test-cluster",
		version:     "1.0.0",
	}
	collector := NewCollector(db, infoProvider)

	// Collect metrics
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify metrics output contains new metric names
	if !strings.Contains(metrics, "kubernetes_vulnerability_scanned_instances") {
		t.Error("Expected kubernetes_vulnerability_scanned_instances metric")
	}

	// Verify composite labels
	if !strings.Contains(metrics, `cluster_name="test-cluster"`) {
		t.Error("Expected cluster_name label")
	}

	if !strings.Contains(metrics, `instance_type="CONTAINER"`) {
		t.Error("Expected instance_type label")
	}

	if !strings.Contains(metrics, `cluster_name_namespace="test-cluster.test-namespace"`) {
		t.Error("Expected cluster_name_namespace composite label")
	}

	if !strings.Contains(metrics, `cluster_name_namespace_pod_name_container_name="test-cluster.test-namespace.test-pod.test-container"`) {
		t.Error("Expected cluster_name_namespace_pod_name_container_name composite label")
	}

	if !strings.Contains(metrics, `namespace="test-namespace"`) {
		t.Error("Expected namespace label")
	}

	if !strings.Contains(metrics, `pod_name="test-pod"`) {
		t.Error("Expected pod_name label")
	}

	if !strings.Contains(metrics, `container_name="test-container"`) {
		t.Error("Expected container_name label")
	}

	if !strings.Contains(metrics, `image="nginx:latest"`) {
		t.Error("Expected image label")
	}

	if !strings.Contains(metrics, `node_name="test-node"`) {
		t.Error("Expected node_name label")
	}
}

func TestEscapeLabelValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`normal`, `normal`},
		{`with"quote`, `with\"quote`},
		{`with\backslash`, `with\\backslash`},
		{"with\newline", `with\newline`},
		{`multi"ple\special`, `multi\"ple\\special`},
	}

	for _, tt := range tests {
		result := escapeLabelValue(tt.input)
		if result != tt.expected {
			t.Errorf("escapeLabelValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCollector_EmptyDatabase(t *testing.T) {
	// Create empty in-memory database
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create collector
	infoProvider := &MockInfoProvider{
		clusterName: "test-cluster",
		version:     "1.0.0",
	}
	collector := NewCollector(db, infoProvider)

	// Collect metrics from empty database
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// With empty database, should return empty string (no metrics)
	if metrics != "" {
		t.Errorf("Expected empty metrics for empty database, got: %s", metrics)
	}
}

func TestCollector_VulnerabilityResults(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Add test instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "prod-namespace",
			Pod:       "web-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Repository: "nginx",
			Tag:        "1.21",
			Digest:     "sha256:vulnerable123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	imageID, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Add vulnerability data directly to vulnerabilities table
	conn := db.GetConnection()
	_, err = conn.Exec(`
		INSERT INTO vulnerabilities (image_id, cve_id, severity, fix_status, count)
		VALUES (?, 'CVE-2021-1234', 'Critical', 'fixed', 2),
		       (?, 'CVE-2021-5678', 'High', 'not-fixed', 1),
		       (?, 'CVE-2020-9999', 'Medium', 'wont-fix', 3)
	`, imageID, imageID, imageID)
	if err != nil {
		t.Fatalf("Failed to insert vulnerabilities: %v", err)
	}

	// Create collector and collect metrics
	infoProvider := &MockInfoProvider{
		clusterName: "test-cluster",
		version:     "1.0.0",
	}
	collector := NewCollector(db, infoProvider)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify vulnerability results metric exists
	if !strings.Contains(metrics, "kubernetes_vulnerability_results") {
		t.Error("Expected kubernetes_vulnerability_results metric")
	}

	// Verify each CVE is present with correct labels
	if !strings.Contains(metrics, `vulnerability_id="CVE-2021-1234"`) {
		t.Error("Expected CVE-2021-1234 in results")
	}
	if !strings.Contains(metrics, `severity="Critical"`) {
		t.Error("Expected Critical severity")
	}
	if !strings.Contains(metrics, `fix_state="fixed"`) {
		t.Error("Expected fix_state=fixed")
	}

	// Verify counts are correct
	if !strings.Contains(metrics, `vulnerability_id="CVE-2021-1234"`) || !strings.Contains(metrics, "} 2") {
		t.Error("Expected count of 2 for CVE-2021-1234")
	}

	// Verify composite labels in vulnerability results
	if !strings.Contains(metrics, `cluster_name_namespace_pod_name_container_name="test-cluster.prod-namespace.web-pod.nginx"`) {
		t.Error("Expected composite label in vulnerability results")
	}
}

func TestCollector_SBOMPackages(t *testing.T) {
	// Create in-memory database
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Add test instance
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "app-namespace",
			Pod:       "backend-pod",
			Container: "api",
		},
		Image: containers.ImageID{
			Repository: "myapp/backend",
			Tag:        "v2.0",
			Digest:     "sha256:package123",
		},
		NodeName:         "worker-2",
		ContainerRuntime: "docker",
	}

	imageID, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Add package data directly to packages table
	conn := db.GetConnection()
	_, err = conn.Exec(`
		INSERT INTO packages (image_id, name, version, type, number_of_instances)
		VALUES (?, 'openssl', '1.1.1k', 'deb', 1),
		       (?, 'curl', '7.68.0', 'deb', 1),
		       (?, 'busybox', '1.33.1', 'apk', 2)
	`, imageID, imageID, imageID)
	if err != nil {
		t.Fatalf("Failed to insert packages: %v", err)
	}

	// Create collector and collect metrics
	infoProvider := &MockInfoProvider{
		clusterName: "test-cluster",
		version:     "1.0.0",
	}
	collector := NewCollector(db, infoProvider)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify SBOM metric exists
	if !strings.Contains(metrics, "kubernetes_vulnerability_sbom") {
		t.Error("Expected kubernetes_vulnerability_sbom metric")
	}

	// Verify each package is present with correct labels
	if !strings.Contains(metrics, `name="openssl"`) {
		t.Error("Expected openssl package in SBOM")
	}
	if !strings.Contains(metrics, `version="1.1.1k"`) {
		t.Error("Expected version 1.1.1k")
	}
	if !strings.Contains(metrics, `type="deb"`) {
		t.Error("Expected type=deb")
	}

	// Verify all packages are present
	if !strings.Contains(metrics, `name="curl"`) {
		t.Error("Expected curl package")
	}
	if !strings.Contains(metrics, `name="busybox"`) {
		t.Error("Expected busybox package")
	}
	if !strings.Contains(metrics, `type="apk"`) {
		t.Error("Expected type=apk for busybox")
	}

	// Verify composite labels in SBOM
	if !strings.Contains(metrics, `cluster_name_namespace_pod_name_container_name="test-cluster.app-namespace.backend-pod.api"`) {
		t.Error("Expected composite label in SBOM metrics")
	}

	// Verify SBOM metrics have value of 1
	lines := strings.Split(metrics, "\n")
	for _, line := range lines {
		if strings.Contains(line, "kubernetes_vulnerability_sbom{") {
			if !strings.HasSuffix(line, " 1") {
				t.Errorf("Expected SBOM metric to have value 1, got: %s", line)
			}
		}
	}
}
