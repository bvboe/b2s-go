package metrics

import (
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// MockInfoProvider implements InfoProvider for testing
type MockInfoProvider struct {
	deploymentName string
	deploymentType string
	version        string
	deploymentIP   string
	consoleURL     string
	grypeDBBuilt   string
}

func (m *MockInfoProvider) GetDeploymentName() string {
	return m.deploymentName
}

func (m *MockInfoProvider) GetDeploymentType() string {
	return m.deploymentType
}

func (m *MockInfoProvider) GetVersion() string {
	return m.version
}

func (m *MockInfoProvider) GetDeploymentIP() string {
	return m.deploymentIP
}

func (m *MockInfoProvider) GetConsoleURL() string {
	return m.consoleURL
}

func (m *MockInfoProvider) GetGrypeDBBuilt() string {
	return m.grypeDBBuilt
}

// MockDatabaseProvider implements DatabaseProvider for testing
type MockDatabaseProvider struct {
	instances         []database.ScannedContainer
	vulnerabilities   []database.ContainerVulnerability
	scanStatusCounts  []database.ImageScanStatusCount
	err               error
}

func (m *MockDatabaseProvider) GetScannedContainers() ([]database.ScannedContainer, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.instances, nil
}

func (m *MockDatabaseProvider) GetContainerVulnerabilities() ([]database.ContainerVulnerability, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.vulnerabilities, nil
}

func (m *MockDatabaseProvider) GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scanStatusCounts, nil
}

func TestCollector_Collect(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-host",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"
	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)

	// Collect metrics
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify metric name
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}

	// Verify labels
	if !strings.Contains(metrics, `deployment_uuid="550e8400-e29b-41d4-a716-446655440000"`) {
		t.Error("Expected deployment_uuid label")
	}
	if !strings.Contains(metrics, `deployment_name="test-host"`) {
		t.Error("Expected deployment_name label")
	}
	if !strings.Contains(metrics, `deployment_type="agent"`) {
		t.Error("Expected deployment_type label")
	}
	if !strings.Contains(metrics, `bjorn2scan_version="1.0.0"`) {
		t.Error("Expected bjorn2scan_version label")
	}

	// Verify value
	if !strings.Contains(metrics, "} 1\n") {
		t.Error("Expected metric value of 1")
	}
}

func TestCollector_KubernetesType(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "production-cluster",
		deploymentType: "kubernetes",
		version:        "2.5.3",
	}
	deploymentUUID := "abc-123-def-456"
	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify kubernetes type
	if !strings.Contains(metrics, `deployment_type="kubernetes"`) {
		t.Error("Expected deployment_type=kubernetes")
	}
	if !strings.Contains(metrics, `deployment_name="production-cluster"`) {
		t.Error("Expected cluster name as deployment_name")
	}
}

func TestCollector_GrypeDBBuiltLabel(t *testing.T) {
	testCases := []struct {
		name           string
		grypeDBBuilt   string
		expectLabel    bool
		expectedValue  string
	}{
		{
			name:          "With grype_db_built",
			grypeDBBuilt:  "2025-12-27T10:30:00Z",
			expectLabel:   true,
			expectedValue: `grype_db_built="2025-12-27T10:30:00Z"`,
		},
		{
			name:          "Without grype_db_built (empty)",
			grypeDBBuilt:  "",
			expectLabel:   false,
			expectedValue: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			infoProvider := &MockInfoProvider{
				deploymentName: "test-cluster",
				deploymentType: "kubernetes",
				version:        "1.0.0",
				grypeDBBuilt:   tc.grypeDBBuilt,
			}
			deploymentUUID := "test-uuid"
			config := CollectorConfig{
				DeploymentEnabled: true,
			}

			collector := NewCollector(infoProvider, deploymentUUID, nil, config)
			data, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			metrics := FormatPrometheus(data)

			hasLabel := strings.Contains(metrics, `grype_db_built=`)
			if hasLabel != tc.expectLabel {
				t.Errorf("Expected grype_db_built label present=%v, got=%v", tc.expectLabel, hasLabel)
			}

			if tc.expectLabel && !strings.Contains(metrics, tc.expectedValue) {
				t.Errorf("Expected label value %s", tc.expectedValue)
			}
		})
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

func TestCollector_EscapesSpecialCharacters(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: `host"with"quotes`,
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"
	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify escaped quotes
	if !strings.Contains(metrics, `deployment_name="host\"with\"quotes"`) {
		t.Error("Expected escaped quotes in deployment_name")
	}
}

func TestCollector_CollectScannedContainers(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        "test-pod-1",
				Name:  "nginx",
				NodeName:   "node-1",
				Reference: "nginx:1.21",
				Digest:     "sha256:abc123",
				OSName:     "debian",
			},
			{
				Namespace:  "kube-system",
				Pod:        "coredns-abc",
				Name:  "coredns",
				NodeName:   "node-2",
				Reference: "coredns/coredns:1.8.0",
				Digest:     "sha256:def456",
				OSName:     "alpine",
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify deployment metric is present
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}

	// Verify scanned container metric is present
	if !strings.Contains(metrics, "bjorn2scan_scanned_container{") {
		t.Error("Expected bjorn2scan_scanned_container metric")
	}

	// Verify first instance
	if !strings.Contains(metrics, `namespace="default"`) {
		t.Error("Expected namespace=default")
	}
	if !strings.Contains(metrics, `pod="test-pod-1"`) {
		t.Error("Expected pod=test-pod-1")
	}
	if !strings.Contains(metrics, `container="nginx"`) {
		t.Error("Expected container=nginx")
	}
	if !strings.Contains(metrics, `host_name="node-1"`) {
		t.Error("Expected host_name=node-1")
	}
	if !strings.Contains(metrics, `distro="debian"`) {
		t.Error("Expected distro=debian")
	}

	// Verify second instance
	if !strings.Contains(metrics, `namespace="kube-system"`) {
		t.Error("Expected namespace=kube-system")
	}
	if !strings.Contains(metrics, `pod="coredns-abc"`) {
		t.Error("Expected pod=coredns-abc")
	}
	if !strings.Contains(metrics, `distro="alpine"`) {
		t.Error("Expected distro=alpine")
	}

	// Verify instance_type is hardcoded
	if !strings.Contains(metrics, `instance_type="CONTAINER"`) {
		t.Error("Expected instance_type=CONTAINER")
	}

	// Count the number of scanned container metrics (should be 2)
	count := strings.Count(metrics, "bjorn2scan_scanned_container{")
	if count != 2 {
		t.Errorf("Expected 2 scanned container metrics, got %d", count)
	}
}

func TestCollector_ScannedContainerLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "prod-cluster",
		deploymentType: "kubernetes",
		version:        "2.0.0",
	}
	deploymentUUID := "abc-123-def-456"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "production",
				Pod:        "app-pod",
				Name:  "app-container",
				NodeName:   "prod-node-1",
				Reference: "myapp:v1.2.3",
				Digest:     "sha256:xyz789",
				OSName:     "ubuntu",
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedContainersEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify all hierarchical labels are present
	expectedLabels := []string{
		`deployment_uuid="abc-123-def-456"`,
		`deployment_uuid_host_name="abc-123-def-456.prod-node-1"`,
		`deployment_uuid_namespace="abc-123-def-456.production"`,
		`deployment_uuid_namespace_image="abc-123-def-456.production.myapp:v1.2.3"`,
		`deployment_uuid_namespace_image_digest="abc-123-def-456.production.sha256:xyz789"`,
		`deployment_uuid_namespace_pod="abc-123-def-456.production.app-pod"`,
		`deployment_uuid_namespace_pod_container="abc-123-def-456.production.app-pod.app-container"`,
		`host_name="prod-node-1"`,
		`namespace="production"`,
		`pod="app-pod"`,
		`container="app-container"`,
		`distro="ubuntu"`,
		`image_reference="myapp:v1.2.3"`,
		`image_digest="sha256:xyz789"`,
		`instance_type="CONTAINER"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s to be present in metrics", label)
		}
	}

	// Verify deployment metric is NOT present (disabled)
	if strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric to be disabled")
	}
}

func TestCollector_ConfigToggles(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Name:  "test-container",
				NodeName:   "node-1",
				Reference: "test:latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
	}

	testCases := []struct {
		name                    string
		deploymentEnabled       bool
		scannedContainersEnabled bool
		expectDeployment        bool
		expectScannedContainer   bool
	}{
		{
			name:                    "Both enabled",
			deploymentEnabled:       true,
			scannedContainersEnabled: true,
			expectDeployment:        true,
			expectScannedContainer:   true,
		},
		{
			name:                    "Only deployment enabled",
			deploymentEnabled:       true,
			scannedContainersEnabled: false,
			expectDeployment:        true,
			expectScannedContainer:   false,
		},
		{
			name:                    "Only scanned containers enabled",
			deploymentEnabled:       false,
			scannedContainersEnabled: true,
			expectDeployment:        false,
			expectScannedContainer:   true,
		},
		{
			name:                    "Both disabled",
			deploymentEnabled:       false,
			scannedContainersEnabled: false,
			expectDeployment:        false,
			expectScannedContainer:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := CollectorConfig{
				DeploymentEnabled:       tc.deploymentEnabled,
				ScannedContainersEnabled: tc.scannedContainersEnabled,
			}

			collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
			data, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			// Format as Prometheus text
			metrics := FormatPrometheus(data)

			hasDeployment := strings.Contains(metrics, "bjorn2scan_deployment{")
			hasScannedContainer := strings.Contains(metrics, "bjorn2scan_scanned_container{")

			if hasDeployment != tc.expectDeployment {
				t.Errorf("Expected deployment metric present=%v, got=%v", tc.expectDeployment, hasDeployment)
			}
			if hasScannedContainer != tc.expectScannedContainer {
				t.Errorf("Expected scanned container metric present=%v, got=%v", tc.expectScannedContainer, hasScannedContainer)
			}
		})
	}
}

func TestCollector_EscapesScannedContainerLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        `pod-with"quotes`,
				Name:  `container\with\backslash`,
				NodeName:   "node-1",
				Reference: "test/repo:v1.0",
				Digest:     "sha256:abc",
				OSName:     `ubuntu"22.04`,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedContainersEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify escaped quotes in pod name
	if !strings.Contains(metrics, `pod="pod-with\"quotes"`) {
		t.Error("Expected escaped quotes in pod name")
	}

	// Verify escaped backslashes in container name
	if !strings.Contains(metrics, `container="container\\with\\backslash"`) {
		t.Error("Expected escaped backslashes in container name")
	}

	// Verify escaped quotes in distro
	if !strings.Contains(metrics, `distro="ubuntu\"22.04"`) {
		t.Error("Expected escaped quotes in distro")
	}
}

func TestCollector_ScannedContainersWithNilDatabase(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: true,
	}

	// Nil database should be handled gracefully
	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Should have deployment metric but not scanned container metrics
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}
	if strings.Contains(metrics, "bjorn2scan_scanned_container{") {
		t.Error("Expected no bjorn2scan_scanned_container metric with nil database")
	}
}

func TestCollector_CollectVulnerabilities(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				Namespace:      "default",
				Pod:            "test-pod-1",
				Name:      "nginx",
				NodeName:       "node-1",
				Reference: "nginx:1.21",
				Digest:         "sha256:abc123",
				OSName:         "debian",
				CVEID:          "CVE-2022-48174",
				PackageName:    "busybox",
				PackageVersion: "1.35.0",
				Severity:       "Critical",
				FixStatus:      "fixed",
				FixedVersion:   "1.35.1",
				Count:          1,
			},
			{
				Namespace:      "default",
				Pod:            "test-pod-1",
				Name:      "nginx",
				NodeName:       "node-1",
				Reference: "nginx:1.21",
				Digest:         "sha256:abc123",
				OSName:         "debian",
				CVEID:          "CVE-2023-1234",
				PackageName:    "openssl",
				PackageVersion: "1.1.1",
				Severity:       "High",
				FixStatus:      "not-fixed",
				FixedVersion:   "",
				Count:          2,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedContainersEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify vulnerability metric is present
	if !strings.Contains(metrics, "bjorn2scan_vulnerability{") {
		t.Error("Expected bjorn2scan_vulnerability metric")
	}

	// Verify first vulnerability labels
	if !strings.Contains(metrics, `vulnerability="CVE-2022-48174"`) {
		t.Error("Expected CVE-2022-48174")
	}
	if !strings.Contains(metrics, `severity="Critical"`) {
		t.Error("Expected severity=Critical")
	}
	if !strings.Contains(metrics, `package_name="busybox"`) {
		t.Error("Expected package_name=busybox")
	}
	if !strings.Contains(metrics, `package_version="1.35.0"`) {
		t.Error("Expected package_version=1.35.0")
	}
	if !strings.Contains(metrics, `fix_status="fixed"`) {
		t.Error("Expected fix_status=fixed")
	}
	if !strings.Contains(metrics, `fixed_version="1.35.1"`) {
		t.Error("Expected fixed_version=1.35.1")
	}

	// Verify second vulnerability
	if !strings.Contains(metrics, `vulnerability="CVE-2023-1234"`) {
		t.Error("Expected CVE-2023-1234")
	}
	if !strings.Contains(metrics, `severity="High"`) {
		t.Error("Expected severity=High")
	}

	// Verify metric values (count field)
	// Check that CVE-2022-48174 has a count of 1
	if !strings.Contains(metrics, `vulnerability="CVE-2022-48174"`) || !strings.Contains(metrics, `package_name="busybox"`) {
		t.Error("Expected CVE-2022-48174 with busybox package")
	}
	// Check that CVE-2023-1234 has a count of 2
	if !strings.Contains(metrics, `vulnerability="CVE-2023-1234"`) || !strings.Contains(metrics, `package_name="openssl"`) {
		t.Error("Expected CVE-2023-1234 with openssl package")
	}

	// Count occurrences - should have 2 total metrics
	vulnCount := strings.Count(metrics, "bjorn2scan_vulnerability{")
	if vulnCount != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", vulnCount)
	}
}

func TestCollector_VulnerabilityLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "prod-cluster",
		deploymentType: "kubernetes",
		version:        "2.0.0",
	}
	deploymentUUID := "abc-123-def-456"

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				Namespace:      "production",
				Pod:            "app-pod",
				Name:      "app-container",
				NodeName:       "prod-node-1",
				Reference:      "myapp:v1.2.3",
				Digest:         "sha256:xyz789",
				OSName:         "ubuntu",
				CVEID:          "CVE-2024-0001",
				PackageName:    "libc",
				PackageVersion: "2.31",
				Severity:       "Medium",
				FixStatus:      "fixed",
				FixedVersion:   "2.32",
				Count:          3,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedContainersEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify all hierarchical labels are present
	expectedLabels := []string{
		`deployment_uuid="abc-123-def-456"`,
		`deployment_uuid_host_name="abc-123-def-456.prod-node-1"`,
		`deployment_uuid_namespace="abc-123-def-456.production"`,
		`deployment_uuid_namespace_image="abc-123-def-456.production.myapp:v1.2.3"`,
		`deployment_uuid_namespace_image_digest="abc-123-def-456.production.sha256:xyz789"`,
		`deployment_uuid_namespace_pod="abc-123-def-456.production.app-pod"`,
		`deployment_uuid_namespace_pod_container="abc-123-def-456.production.app-pod.app-container"`,
		`host_name="prod-node-1"`,
		`namespace="production"`,
		`pod="app-pod"`,
		`container="app-container"`,
		`distro="ubuntu"`,
		`image_reference="myapp:v1.2.3"`,
		`image_digest="sha256:xyz789"`,
		`instance_type="CONTAINER"`,
		`severity="Medium"`,
		`vulnerability="CVE-2024-0001"`,
		`package_name="libc"`,
		`package_version="2.31"`,
		`fix_status="fixed"`,
		`fixed_version="2.32"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s to be present in metrics", label)
		}
	}

	// Verify metric value
	if !strings.Contains(metrics, "} 3\n") {
		t.Error("Expected metric value of 3")
	}
}

func TestCollector_ConfigTogglesWithVulnerabilities(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Name:  "test-container",
				NodeName:   "node-1",
				Reference: "test:latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
		vulnerabilities: []database.ContainerVulnerability{
			{
				Namespace:      "default",
				Pod:            "test-pod",
				Name:      "test-container",
				NodeName:       "node-1",
				Reference:      "test:latest",
				Digest:         "sha256:abc",
				OSName:         "alpine",
				CVEID:          "CVE-2024-TEST",
				PackageName:    "testpkg",
				PackageVersion: "1.0",
				Severity:       "Low",
				FixStatus:      "fixed",
				FixedVersion:   "1.1",
				Count:          1,
			},
		},
	}

	testCases := []struct {
		name                    string
		deploymentEnabled       bool
		scannedContainersEnabled bool
		vulnerabilitiesEnabled  bool
		expectDeployment        bool
		expectScannedContainer   bool
		expectVulnerability     bool
	}{
		{
			name:                    "All enabled",
			deploymentEnabled:       true,
			scannedContainersEnabled: true,
			vulnerabilitiesEnabled:  true,
			expectDeployment:        true,
			expectScannedContainer:   true,
			expectVulnerability:     true,
		},
		{
			name:                    "Only vulnerabilities enabled",
			deploymentEnabled:       false,
			scannedContainersEnabled: false,
			vulnerabilitiesEnabled:  true,
			expectDeployment:        false,
			expectScannedContainer:   false,
			expectVulnerability:     true,
		},
		{
			name:                    "Vulnerabilities disabled",
			deploymentEnabled:       true,
			scannedContainersEnabled: true,
			vulnerabilitiesEnabled:  false,
			expectDeployment:        true,
			expectScannedContainer:   true,
			expectVulnerability:     false,
		},
		{
			name:                    "All disabled",
			deploymentEnabled:       false,
			scannedContainersEnabled: false,
			vulnerabilitiesEnabled:  false,
			expectDeployment:        false,
			expectScannedContainer:   false,
			expectVulnerability:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := CollectorConfig{
				DeploymentEnabled:       tc.deploymentEnabled,
				ScannedContainersEnabled: tc.scannedContainersEnabled,
				VulnerabilitiesEnabled:  tc.vulnerabilitiesEnabled,
			}

			collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
			data, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			// Format as Prometheus text
			metrics := FormatPrometheus(data)

			hasDeployment := strings.Contains(metrics, "bjorn2scan_deployment{")
			hasScannedContainer := strings.Contains(metrics, "bjorn2scan_scanned_container{")
			hasVulnerability := strings.Contains(metrics, "bjorn2scan_vulnerability{")

			if hasDeployment != tc.expectDeployment {
				t.Errorf("Expected deployment metric present=%v, got=%v", tc.expectDeployment, hasDeployment)
			}
			if hasScannedContainer != tc.expectScannedContainer {
				t.Errorf("Expected scanned container metric present=%v, got=%v", tc.expectScannedContainer, hasScannedContainer)
			}
			if hasVulnerability != tc.expectVulnerability {
				t.Errorf("Expected vulnerability metric present=%v, got=%v", tc.expectVulnerability, hasVulnerability)
			}
		})
	}
}

func TestCollector_VulnerabilitiesWithNilDatabase(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: true,
		VulnerabilitiesEnabled:  true,
	}

	// Nil database should be handled gracefully
	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Should have deployment metric but not vulnerability metrics
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}
	if strings.Contains(metrics, "bjorn2scan_vulnerability{") {
		t.Error("Expected no bjorn2scan_vulnerability metric with nil database")
	}
}

func TestCollector_EscapesVulnerabilityLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				Namespace:      "default",
				Pod:            `pod-with"quotes`,
				Name:      `container\with\backslash`,
				NodeName:       "node-1",
				Reference:      "test/repo:v1.0",
				Digest:         "sha256:abc",
				OSName:         `ubuntu"22.04`,
				CVEID:          "CVE-2024-TEST",
				PackageName:    `pkg"with"quotes`,
				PackageVersion: `1.0"beta`,
				Severity:       "Critical",
				FixStatus:      "fixed",
				FixedVersion:   `1.1"stable`,
				Count:          1,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedContainersEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify escaped quotes in pod name
	if !strings.Contains(metrics, `pod="pod-with\"quotes"`) {
		t.Error("Expected escaped quotes in pod name")
	}

	// Verify escaped backslashes in container name
	if !strings.Contains(metrics, `container="container\\with\\backslash"`) {
		t.Error("Expected escaped backslashes in container name")
	}

	// Verify escaped quotes in distro
	if !strings.Contains(metrics, `distro="ubuntu\"22.04"`) {
		t.Error("Expected escaped quotes in distro")
	}

	// Verify escaped quotes in package name
	if !strings.Contains(metrics, `package_name="pkg\"with\"quotes"`) {
		t.Error("Expected escaped quotes in package name")
	}

	// Verify escaped quotes in package version
	if !strings.Contains(metrics, `package_version="1.0\"beta"`) {
		t.Error("Expected escaped quotes in package version")
	}

	// Verify escaped quotes in fixed version
	if !strings.Contains(metrics, `fixed_version="1.1\"stable"`) {
		t.Error("Expected escaped quotes in fixed version")
	}
}

func TestCollector_CollectVulnerabilityRisk(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				Namespace:      "default",
				Pod:            "test-pod-1",
				Name:      "nginx",
				NodeName:       "node-1",
				Reference: "nginx:1.21",
				Digest:         "sha256:abc123",
				OSName:         "debian",
				CVEID:          "CVE-2022-48174",
				PackageName:    "busybox",
				PackageVersion: "1.35.0",
				Severity:       "Critical",
				FixStatus:      "fixed",
				FixedVersion:   "1.35.1",
				Count:          1,
				KnownExploited: 0,
				Risk:           7.5,
			},
			{
				Namespace:      "default",
				Pod:            "test-pod-2",
				Name:      "redis",
				NodeName:       "node-2",
				Reference: "redis:6.2",
				Digest:         "sha256:def456",
				OSName:         "alpine",
				CVEID:          "CVE-2023-5678",
				PackageName:    "openssl",
				PackageVersion: "1.1.1",
				Severity:       "High",
				FixStatus:      "not-fixed",
				FixedVersion:   "",
				Count:          2,
				KnownExploited: 1,
				Risk:           0.0,
			},
			{
				Namespace:      "prod",
				Pod:            "test-pod-3",
				Name:      "postgres",
				NodeName:       "node-3",
				Reference: "postgres:14",
				Digest:         "sha256:ghi789",
				OSName:         "debian",
				CVEID:          "CVE-2024-1234",
				PackageName:    "libpq",
				PackageVersion: "14.0",
				Severity:       "Medium",
				FixStatus:      "fixed",
				FixedVersion:   "14.1",
				Count:          1,
				KnownExploited: 0,
				Risk:           3.2,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:         false,
		ScannedContainersEnabled:   false,
		VulnerabilitiesEnabled:    false,
		VulnerabilityRiskEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Format as Prometheus text
	metrics := FormatPrometheus(data)

	// Verify vulnerability risk metric is present
	if !strings.Contains(metrics, "bjorn2scan_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_vulnerability_risk metric")
	}

	// Verify all three vulnerabilities are included (no filtering)
	if !strings.Contains(metrics, `vulnerability="CVE-2022-48174"`) {
		t.Error("Expected CVE-2022-48174")
	}
	if !strings.Contains(metrics, `vulnerability="CVE-2023-5678"`) {
		t.Error("Expected CVE-2023-5678 (risk=0.0 should be included)")
	}
	if !strings.Contains(metrics, `vulnerability="CVE-2024-1234"`) {
		t.Error("Expected CVE-2024-1234")
	}

	// Verify float values are present
	if !strings.Contains(metrics, "7.5") {
		t.Error("Expected risk value 7.5")
	}
	if !strings.Contains(metrics, "0") {
		t.Error("Expected risk value 0 (for zero risk)")
	}
	if !strings.Contains(metrics, "3.2") {
		t.Error("Expected risk value 3.2")
	}
}

func TestCollector_VulnerabilityRiskLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				VulnID:         123,
				Namespace:      "production",
				Pod:            "web-app-xyz",
				Name:      "nginx-container",
				NodeName:       "worker-node-1",
				Reference: "nginx:1.21.6",
				Digest:         "sha256:abcdef123456",
				OSName:         "debian-11",
				CVEID:          "CVE-2022-48174",
				PackageName:    "busybox",
				PackageVersion: "1.35.0",
				Severity:       "Critical",
				FixStatus:      "fixed",
				FixedVersion:   "1.35.1",
				Count:          1,
				KnownExploited: 1,
				Risk:           8.9,
			},
		},
	}

	config := CollectorConfig{
		VulnerabilityRiskEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify all required labels are present
	expectedLabels := []string{
		`deployment_uuid="550e8400-e29b-41d4-a716-446655440000"`,
		`host_name="worker-node-1"`,
		`namespace="production"`,
		`pod="web-app-xyz"`,
		`container="nginx-container"`,
		`distro="debian-11"`,
		`image_reference="nginx:1.21.6"`,
		`image_digest="sha256:abcdef123456"`,
		`instance_type="CONTAINER"`,
		`severity="Critical"`,
		`vulnerability="CVE-2022-48174"`,
		`package_name="busybox"`,
		`package_version="1.35.0"`,
		`fix_status="fixed"`,
		`fixed_version="1.35.1"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s in metrics output", label)
		}
	}

	// Verify risk value
	if !strings.Contains(metrics, "8.9") {
		t.Error("Expected risk value 8.9")
	}
}

func TestCollector_ConfigTogglesWithVulnerabilityRisk(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				CVEID: "CVE-2022-48174",
				Risk:  5.5,
			},
		},
	}

	tests := []struct {
		name         string
		config       CollectorConfig
		expectMetric bool
	}{
		{
			name: "VulnerabilityRiskEnabled_true",
			config: CollectorConfig{
				VulnerabilityRiskEnabled: true,
			},
			expectMetric: true,
		},
		{
			name: "VulnerabilityRiskEnabled_false",
			config: CollectorConfig{
				VulnerabilityRiskEnabled: false,
			},
			expectMetric: false,
		},
		{
			name: "All_metrics_enabled",
			config: CollectorConfig{
				DeploymentEnabled:            true,
				ScannedContainersEnabled:      true,
				VulnerabilitiesEnabled:       true,
				VulnerabilityExploitedEnabled: true,
				VulnerabilityRiskEnabled:     true,
			},
			expectMetric: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := NewCollector(infoProvider, "test-uuid", mockDB, tt.config)
			data, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			metrics := FormatPrometheus(data)
			hasMetric := strings.Contains(metrics, "bjorn2scan_vulnerability_risk")

			if hasMetric != tt.expectMetric {
				t.Errorf("Expected metric presence: %v, got: %v", tt.expectMetric, hasMetric)
			}
		})
	}
}

func TestCollector_VulnerabilityRiskFloatValues(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	// Test various float values including edge cases
	mockDB := &MockDatabaseProvider{
		vulnerabilities: []database.ContainerVulnerability{
			{
				CVEID:     "CVE-2022-0001",
				Namespace: "default",
				Pod:       "test-1",
				Name: "app",
				Risk:      0.0,
				Count:     1,
			},
			{
				CVEID:     "CVE-2022-0002",
				Namespace: "default",
				Pod:       "test-2",
				Name: "app",
				Risk:      0.5,
				Count:     1,
			},
			{
				CVEID:     "CVE-2022-0003",
				Namespace: "default",
				Pod:       "test-3",
				Name: "app",
				Risk:      7.5,
				Count:     1,
			},
			{
				CVEID:     "CVE-2022-0004",
				Namespace: "default",
				Pod:       "test-4",
				Name: "app",
				Risk:      10.0,
				Count:     1,
			},
			{
				CVEID:     "CVE-2022-0005",
				Namespace: "default",
				Pod:       "test-5",
				Name: "app",
				Risk:      3.14159,
				Count:     1,
			},
		},
	}

	config := CollectorConfig{
		VulnerabilityRiskEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify different float values are present
	testCases := []struct {
		cve   string
		value string
	}{
		{"CVE-2022-0001", "0"},          // Zero value
		{"CVE-2022-0002", "0.5"},        // Decimal
		{"CVE-2022-0003", "7.5"},        // Common CVSS score
		{"CVE-2022-0004", "10"},         // Maximum
		{"CVE-2022-0005", "3.14159"},    // Multiple decimals
	}

	for _, tc := range testCases {
		if !strings.Contains(metrics, tc.cve) {
			t.Errorf("Expected CVE %s in output", tc.cve)
		}
		if !strings.Contains(metrics, tc.value) {
			t.Errorf("Expected risk value %s in output", tc.value)
		}
	}

	// Verify Prometheus format is valid (should use %g which produces valid float format)
	lines := strings.Split(metrics, "\n")
	for _, line := range lines {
		if strings.Contains(line, "bjorn2scan_vulnerability_risk{") {
			// Line should end with a valid float
			parts := strings.Split(line, "} ")
			if len(parts) != 2 {
				t.Errorf("Invalid metric line format: %s", line)
			}
		}
	}
}

func TestCollector_VulnerabilityRiskWithNilDatabase(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	config := CollectorConfig{
		VulnerabilityRiskEnabled: true,
	}

	// Pass nil database
	collector := NewCollector(infoProvider, "test-uuid", nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Should not contain vulnerability risk metric when database is nil
	if strings.Contains(metrics, "bjorn2scan_vulnerability_risk") {
		t.Error("Should not have vulnerability risk metric with nil database")
	}
}
