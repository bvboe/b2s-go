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

// MockDatabaseProvider implements DatabaseProvider for testing
type MockDatabaseProvider struct {
	instances        []database.ScannedContainerInstance
	vulnerabilities  []database.VulnerabilityInstance
	err              error
}

func (m *MockDatabaseProvider) GetScannedContainerInstances() ([]database.ScannedContainerInstance, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.instances, nil
}

func (m *MockDatabaseProvider) GetVulnerabilityInstances() ([]database.VulnerabilityInstance, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.vulnerabilities, nil
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
		ScannedInstancesEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)

	// Collect metrics
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

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
		ScannedInstancesEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify kubernetes type
	if !strings.Contains(metrics, `deployment_type="kubernetes"`) {
		t.Error("Expected deployment_type=kubernetes")
	}
	if !strings.Contains(metrics, `deployment_name="production-cluster"`) {
		t.Error("Expected cluster name as deployment_name")
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
		ScannedInstancesEnabled: false,
	}

	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify escaped quotes
	if !strings.Contains(metrics, `deployment_name="host\"with\"quotes"`) {
		t.Error("Expected escaped quotes in deployment_name")
	}
}

func TestCollector_CollectScannedInstances(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "default",
				Pod:        "test-pod-1",
				Container:  "nginx",
				NodeName:   "node-1",
				Repository: "nginx",
				Tag:        "1.21",
				Digest:     "sha256:abc123",
				OSName:     "debian",
			},
			{
				Namespace:  "kube-system",
				Pod:        "coredns-abc",
				Container:  "coredns",
				NodeName:   "node-2",
				Repository: "coredns/coredns",
				Tag:        "1.8.0",
				Digest:     "sha256:def456",
				OSName:     "alpine",
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedInstancesEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify deployment metric is present
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}

	// Verify scanned instance metric is present
	if !strings.Contains(metrics, "bjorn2scan_scanned_instance{") {
		t.Error("Expected bjorn2scan_scanned_instance metric")
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

	// Count the number of scanned instance metrics (should be 2)
	count := strings.Count(metrics, "bjorn2scan_scanned_instance{")
	if count != 2 {
		t.Errorf("Expected 2 scanned instance metrics, got %d", count)
	}
}

func TestCollector_ScannedInstanceLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "prod-cluster",
		deploymentType: "kubernetes",
		version:        "2.0.0",
	}
	deploymentUUID := "abc-123-def-456"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "production",
				Pod:        "app-pod",
				Container:  "app-container",
				NodeName:   "prod-node-1",
				Repository: "myapp",
				Tag:        "v1.2.3",
				Digest:     "sha256:xyz789",
				OSName:     "ubuntu",
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedInstancesEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify all hierarchical labels are present
	expectedLabels := []string{
		`deployment_uuid="abc-123-def-456"`,
		`deployment_uuid_host_name="abc-123-def-456.prod-node-1"`,
		`deployment_uuid_namespace="abc-123-def-456.production"`,
		`deployment_uuid_namespace_image="abc-123-def-456.production.myapp:v1.2.3"`,
		`deployment_uuid_namespace_image_id="abc-123-def-456.production.sha256:xyz789"`,
		`deployment_uuid_namespace_pod="abc-123-def-456.production.app-pod"`,
		`deployment_uuid_namespace_pod_container="abc-123-def-456.production.app-pod.app-container"`,
		`host_name="prod-node-1"`,
		`namespace="production"`,
		`pod="app-pod"`,
		`container="app-container"`,
		`distro="ubuntu"`,
		`image_repo="myapp"`,
		`image_tag="v1.2.3"`,
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
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Container:  "test-container",
				NodeName:   "node-1",
				Repository: "test",
				Tag:        "latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
	}

	testCases := []struct {
		name                    string
		deploymentEnabled       bool
		scannedInstancesEnabled bool
		expectDeployment        bool
		expectScannedInstance   bool
	}{
		{
			name:                    "Both enabled",
			deploymentEnabled:       true,
			scannedInstancesEnabled: true,
			expectDeployment:        true,
			expectScannedInstance:   true,
		},
		{
			name:                    "Only deployment enabled",
			deploymentEnabled:       true,
			scannedInstancesEnabled: false,
			expectDeployment:        true,
			expectScannedInstance:   false,
		},
		{
			name:                    "Only scanned instances enabled",
			deploymentEnabled:       false,
			scannedInstancesEnabled: true,
			expectDeployment:        false,
			expectScannedInstance:   true,
		},
		{
			name:                    "Both disabled",
			deploymentEnabled:       false,
			scannedInstancesEnabled: false,
			expectDeployment:        false,
			expectScannedInstance:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := CollectorConfig{
				DeploymentEnabled:       tc.deploymentEnabled,
				ScannedInstancesEnabled: tc.scannedInstancesEnabled,
			}

			collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
			metrics, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			hasDeployment := strings.Contains(metrics, "bjorn2scan_deployment{")
			hasScannedInstance := strings.Contains(metrics, "bjorn2scan_scanned_instance{")

			if hasDeployment != tc.expectDeployment {
				t.Errorf("Expected deployment metric present=%v, got=%v", tc.expectDeployment, hasDeployment)
			}
			if hasScannedInstance != tc.expectScannedInstance {
				t.Errorf("Expected scanned instance metric present=%v, got=%v", tc.expectScannedInstance, hasScannedInstance)
			}
		})
	}
}

func TestCollector_EscapesScannedInstanceLabels(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "default",
				Pod:        `pod-with"quotes`,
				Container:  `container\with\backslash`,
				NodeName:   "node-1",
				Repository: "test/repo",
				Tag:        "v1.0",
				Digest:     "sha256:abc",
				OSName:     `ubuntu"22.04`,
			},
		},
	}

	config := CollectorConfig{
		DeploymentEnabled:       false,
		ScannedInstancesEnabled: true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

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

func TestCollector_ScannedInstancesWithNilDatabase(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "test-uuid"

	config := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedInstancesEnabled: true,
	}

	// Nil database should be handled gracefully
	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Should have deployment metric but not scanned instance metrics
	if !strings.Contains(metrics, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}
	if strings.Contains(metrics, "bjorn2scan_scanned_instance{") {
		t.Error("Expected no bjorn2scan_scanned_instance metric with nil database")
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
		vulnerabilities: []database.VulnerabilityInstance{
			{
				Namespace:      "default",
				Pod:            "test-pod-1",
				Container:      "nginx",
				NodeName:       "node-1",
				Repository:     "nginx",
				Tag:            "1.21",
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
				Container:      "nginx",
				NodeName:       "node-1",
				Repository:     "nginx",
				Tag:            "1.21",
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
		ScannedInstancesEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

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
		vulnerabilities: []database.VulnerabilityInstance{
			{
				Namespace:      "production",
				Pod:            "app-pod",
				Container:      "app-container",
				NodeName:       "prod-node-1",
				Repository:     "myapp",
				Tag:            "v1.2.3",
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
		ScannedInstancesEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify all hierarchical labels are present
	expectedLabels := []string{
		`deployment_uuid="abc-123-def-456"`,
		`deployment_uuid_host_name="abc-123-def-456.prod-node-1"`,
		`deployment_uuid_namespace="abc-123-def-456.production"`,
		`deployment_uuid_namespace_image="abc-123-def-456.production.myapp:v1.2.3"`,
		`deployment_uuid_namespace_image_id="abc-123-def-456.production.sha256:xyz789"`,
		`deployment_uuid_namespace_pod="abc-123-def-456.production.app-pod"`,
		`deployment_uuid_namespace_pod_container="abc-123-def-456.production.app-pod.app-container"`,
		`host_name="prod-node-1"`,
		`namespace="production"`,
		`pod="app-pod"`,
		`container="app-container"`,
		`distro="ubuntu"`,
		`image_repo="myapp"`,
		`image_tag="v1.2.3"`,
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
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Container:  "test-container",
				NodeName:   "node-1",
				Repository: "test",
				Tag:        "latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
		vulnerabilities: []database.VulnerabilityInstance{
			{
				Namespace:      "default",
				Pod:            "test-pod",
				Container:      "test-container",
				NodeName:       "node-1",
				Repository:     "test",
				Tag:            "latest",
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
		scannedInstancesEnabled bool
		vulnerabilitiesEnabled  bool
		expectDeployment        bool
		expectScannedInstance   bool
		expectVulnerability     bool
	}{
		{
			name:                    "All enabled",
			deploymentEnabled:       true,
			scannedInstancesEnabled: true,
			vulnerabilitiesEnabled:  true,
			expectDeployment:        true,
			expectScannedInstance:   true,
			expectVulnerability:     true,
		},
		{
			name:                    "Only vulnerabilities enabled",
			deploymentEnabled:       false,
			scannedInstancesEnabled: false,
			vulnerabilitiesEnabled:  true,
			expectDeployment:        false,
			expectScannedInstance:   false,
			expectVulnerability:     true,
		},
		{
			name:                    "Vulnerabilities disabled",
			deploymentEnabled:       true,
			scannedInstancesEnabled: true,
			vulnerabilitiesEnabled:  false,
			expectDeployment:        true,
			expectScannedInstance:   true,
			expectVulnerability:     false,
		},
		{
			name:                    "All disabled",
			deploymentEnabled:       false,
			scannedInstancesEnabled: false,
			vulnerabilitiesEnabled:  false,
			expectDeployment:        false,
			expectScannedInstance:   false,
			expectVulnerability:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := CollectorConfig{
				DeploymentEnabled:       tc.deploymentEnabled,
				ScannedInstancesEnabled: tc.scannedInstancesEnabled,
				VulnerabilitiesEnabled:  tc.vulnerabilitiesEnabled,
			}

			collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
			metrics, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			hasDeployment := strings.Contains(metrics, "bjorn2scan_deployment{")
			hasScannedInstance := strings.Contains(metrics, "bjorn2scan_scanned_instance{")
			hasVulnerability := strings.Contains(metrics, "bjorn2scan_vulnerability{")

			if hasDeployment != tc.expectDeployment {
				t.Errorf("Expected deployment metric present=%v, got=%v", tc.expectDeployment, hasDeployment)
			}
			if hasScannedInstance != tc.expectScannedInstance {
				t.Errorf("Expected scanned instance metric present=%v, got=%v", tc.expectScannedInstance, hasScannedInstance)
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
		ScannedInstancesEnabled: true,
		VulnerabilitiesEnabled:  true,
	}

	// Nil database should be handled gracefully
	collector := NewCollector(infoProvider, deploymentUUID, nil, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

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
		vulnerabilities: []database.VulnerabilityInstance{
			{
				Namespace:      "default",
				Pod:            `pod-with"quotes`,
				Container:      `container\with\backslash`,
				NodeName:       "node-1",
				Repository:     "test/repo",
				Tag:            "v1.0",
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
		ScannedInstancesEnabled: false,
		VulnerabilitiesEnabled:  true,
	}

	collector := NewCollector(infoProvider, deploymentUUID, mockDB, config)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

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
