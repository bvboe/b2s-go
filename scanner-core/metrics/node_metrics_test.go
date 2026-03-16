package metrics

import (
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// MockNodeDatabaseProvider implements NodeDatabaseProvider for testing
type MockNodeDatabaseProvider struct {
	scannedNodes    []nodes.NodeWithStatus
	vulnerabilities []database.NodeVulnerabilityForMetrics
	err             error
}

func (m *MockNodeDatabaseProvider) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scannedNodes, nil
}

func (m *MockNodeDatabaseProvider) GetNodeVulnerabilitiesForMetrics() ([]database.NodeVulnerabilityForMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.vulnerabilities, nil
}

func TestNodeCollector_Collect(t *testing.T) {
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"
	deploymentName := "test-cluster"

	mockDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name:          "node-1",
					Hostname:      "node-1.local",
					OSRelease:     "Ubuntu 22.04.3 LTS",
					KernelVersion: "5.15.0-91-generic",
					Architecture:  "amd64",
				},
			},
		},
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				Hostname:       "node-1.local",
				OSRelease:      "Ubuntu 22.04.3 LTS",
				KernelVersion:  "5.15.0-91-generic",
				Architecture:   "amd64",
				VulnID:         123,
				CVEID:          "CVE-2024-1234",
				Severity:       "Critical",
				Score:          9.8,
				FixStatus:      "fixed",
				FixVersion:     "3.0.13",
				KnownExploited: 1,
				PackageName:    "openssl",
				PackageVersion: "3.0.2",
				PackageType:    "deb",
				Count:          1,
			},
		},
	}

	config := NodeCollectorConfig{
		NodeScannedEnabled:              true,
		NodeVulnerabilitiesEnabled:      true,
		NodeVulnerabilityRiskEnabled:    true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify all metric families are present
	if !strings.Contains(metrics, "bjorn2scan_node_scanned{") {
		t.Error("Expected bjorn2scan_node_scanned metric")
	}
	if !strings.Contains(metrics, "bjorn2scan_node_vulnerability{") {
		t.Error("Expected bjorn2scan_node_vulnerability metric")
	}
	if !strings.Contains(metrics, "bjorn2scan_node_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_node_vulnerability_risk metric")
	}
	if !strings.Contains(metrics, "bjorn2scan_node_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_node_vulnerability_exploited metric")
	}
}

func TestNodeCollector_CollectNodeScanned(t *testing.T) {
	deploymentUUID := "abc-123-def-456"
	deploymentName := "prod-cluster"

	mockDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name:          "worker-1",
					Hostname:      "worker-1.prod.local",
					OSRelease:     "Ubuntu 22.04.3 LTS",
					KernelVersion: "5.15.0-91-generic",
					Architecture:  "amd64",
				},
			},
			{
				Node: nodes.Node{
					Name:          "worker-2",
					Hostname:      "worker-2.prod.local",
					OSRelease:     "Amazon Linux 2023",
					KernelVersion: "6.1.21-1.45.amzn2023",
					Architecture:  "arm64",
				},
			},
		},
	}

	config := NodeCollectorConfig{
		NodeScannedEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify node scanned metrics
	expectedLabels := []string{
		`deployment_uuid="abc-123-def-456"`,
		`deployment_name="prod-cluster"`,
		`node="worker-1"`,
		`hostname="worker-1.prod.local"`,
		`os_release="Ubuntu 22.04.3 LTS"`,
		`kernel_version="5.15.0-91-generic"`,
		`architecture="amd64"`,
		`instance_type="NODE"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s to be present in metrics", label)
		}
	}

	// Verify second node
	if !strings.Contains(metrics, `node="worker-2"`) {
		t.Error("Expected worker-2 node")
	}
	if !strings.Contains(metrics, `architecture="arm64"`) {
		t.Error("Expected arm64 architecture")
	}

	// Count node scanned metrics (should be 2)
	count := strings.Count(metrics, "bjorn2scan_node_scanned{")
	if count != 2 {
		t.Errorf("Expected 2 node scanned metrics, got %d", count)
	}

	// Verify metric value is 1
	if !strings.Contains(metrics, "} 1\n") {
		t.Error("Expected metric value of 1")
	}
}

func TestNodeCollector_CollectNodeVulnerabilities(t *testing.T) {
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"
	deploymentName := "test-cluster"

	mockDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				Hostname:       "node-1.local",
				OSRelease:      "Ubuntu 22.04",
				KernelVersion:  "5.15.0",
				Architecture:   "amd64",
				VulnID:         100,
				CVEID:          "CVE-2024-1234",
				Severity:       "Critical",
				Score:          9.8,
				FixStatus:      "fixed",
				FixVersion:     "1.2.3",
				KnownExploited: 0,
				PackageName:    "openssl",
				PackageVersion: "3.0.2",
				PackageType:    "deb",
				Count:          2,
			},
			{
				NodeName:       "node-1",
				Hostname:       "node-1.local",
				OSRelease:      "Ubuntu 22.04",
				KernelVersion:  "5.15.0",
				Architecture:   "amd64",
				VulnID:         101,
				CVEID:          "CVE-2024-5678",
				Severity:       "High",
				Score:          7.5,
				FixStatus:      "not-fixed",
				FixVersion:     "",
				KnownExploited: 0,
				PackageName:    "curl",
				PackageVersion: "7.81.0",
				PackageType:    "deb",
				Count:          1,
			},
		},
	}

	config := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify vulnerability labels
	expectedLabels := []string{
		`vulnerability="CVE-2024-1234"`,
		`severity="Critical"`,
		`package_name="openssl"`,
		`package_version="3.0.2"`,
		`package_type="deb"`,
		`fix_status="fixed"`,
		`fixed_version="1.2.3"`,
		`vulnerability_id="550e8400-e29b-41d4-a716-446655440000.100"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s to be present in metrics", label)
		}
	}

	// Count vulnerability metrics (should be 2)
	count := strings.Count(metrics, "bjorn2scan_node_vulnerability{")
	if count != 2 {
		t.Errorf("Expected 2 vulnerability metrics, got %d", count)
	}
}

func TestNodeCollector_CollectNodeVulnerabilityRisk(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test-cluster"

	mockDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName: "node-1",
				CVEID:    "CVE-2024-0001",
				Severity: "Critical",
				Score:    9.8,
				Count:    1,
			},
			{
				NodeName: "node-1",
				CVEID:    "CVE-2024-0002",
				Severity: "Medium",
				Score:    5.5,
				Count:    2,
			},
			{
				NodeName: "node-1",
				CVEID:    "CVE-2024-0003",
				Severity: "Low",
				Score:    0.0,
				Count:    1,
			},
		},
	}

	config := NodeCollectorConfig{
		NodeVulnerabilityRiskEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify risk metric is present
	if !strings.Contains(metrics, "bjorn2scan_node_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_node_vulnerability_risk metric")
	}

	// Verify risk values (score * count)
	if !strings.Contains(metrics, "9.8") {
		t.Error("Expected risk value 9.8 (9.8 * 1)")
	}
	if !strings.Contains(metrics, "11") {
		t.Error("Expected risk value 11 (5.5 * 2)")
	}

	// Count risk metrics (should be 3)
	count := strings.Count(metrics, "bjorn2scan_node_vulnerability_risk{")
	if count != 3 {
		t.Errorf("Expected 3 vulnerability risk metrics, got %d", count)
	}
}

func TestNodeCollector_CollectNodeVulnerabilityExploited(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test-cluster"

	mockDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				CVEID:          "CVE-2024-0001",
				Severity:       "Critical",
				KnownExploited: 1, // Known exploited
				Count:          1,
			},
			{
				NodeName:       "node-1",
				CVEID:          "CVE-2024-0002",
				Severity:       "High",
				KnownExploited: 0, // Not known exploited
				Count:          2,
			},
			{
				NodeName:       "node-2",
				CVEID:          "CVE-2024-0003",
				Severity:       "Critical",
				KnownExploited: 1, // Known exploited
				Count:          3,
			},
		},
	}

	config := NodeCollectorConfig{
		NodeVulnerabilityExploitedEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify exploited metric is present
	if !strings.Contains(metrics, "bjorn2scan_node_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_node_vulnerability_exploited metric")
	}

	// Verify only known exploited vulnerabilities are included (2, not 3)
	count := strings.Count(metrics, "bjorn2scan_node_vulnerability_exploited{")
	if count != 2 {
		t.Errorf("Expected 2 exploited vulnerability metrics (only known_exploited > 0), got %d", count)
	}

	// CVE-2024-0002 should NOT be present (not known exploited)
	if strings.Contains(metrics, `vulnerability="CVE-2024-0002"`) {
		t.Error("CVE-2024-0002 should not be present (not known exploited)")
	}
}

func TestNodeCollector_ConfigToggles(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test"

	mockDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name: "node-1",
				},
			},
		},
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				CVEID:          "CVE-2024-TEST",
				Severity:       "High",
				Score:          7.5,
				KnownExploited: 1,
				Count:          1,
			},
		},
	}

	testCases := []struct {
		name                  string
		config                NodeCollectorConfig
		expectScanned         bool
		expectVulnerability   bool
		expectRisk            bool
		expectExploited       bool
	}{
		{
			name: "All enabled",
			config: NodeCollectorConfig{
				NodeScannedEnabled:              true,
				NodeVulnerabilitiesEnabled:      true,
				NodeVulnerabilityRiskEnabled:    true,
				NodeVulnerabilityExploitedEnabled: true,
			},
			expectScanned:       true,
			expectVulnerability: true,
			expectRisk:          true,
			expectExploited:     true,
		},
		{
			name: "Only scanned enabled",
			config: NodeCollectorConfig{
				NodeScannedEnabled: true,
			},
			expectScanned:       true,
			expectVulnerability: false,
			expectRisk:          false,
			expectExploited:     false,
		},
		{
			name: "Only vulnerabilities enabled",
			config: NodeCollectorConfig{
				NodeVulnerabilitiesEnabled: true,
			},
			expectScanned:       false,
			expectVulnerability: true,
			expectRisk:          false,
			expectExploited:     false,
		},
		{
			name: "All disabled",
			config: NodeCollectorConfig{
				NodeScannedEnabled:              false,
				NodeVulnerabilitiesEnabled:      false,
				NodeVulnerabilityRiskEnabled:    false,
				NodeVulnerabilityExploitedEnabled: false,
			},
			expectScanned:       false,
			expectVulnerability: false,
			expectRisk:          false,
			expectExploited:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, tc.config)
			data, err := collector.Collect()
			if err != nil {
				t.Fatalf("Failed to collect metrics: %v", err)
			}

			metrics := FormatPrometheus(data)

			hasScanned := strings.Contains(metrics, "bjorn2scan_node_scanned{")
			hasVulnerability := strings.Contains(metrics, "bjorn2scan_node_vulnerability{")
			hasRisk := strings.Contains(metrics, "bjorn2scan_node_vulnerability_risk{")
			hasExploited := strings.Contains(metrics, "bjorn2scan_node_vulnerability_exploited{")

			if hasScanned != tc.expectScanned {
				t.Errorf("Expected scanned metric present=%v, got=%v", tc.expectScanned, hasScanned)
			}
			if hasVulnerability != tc.expectVulnerability {
				t.Errorf("Expected vulnerability metric present=%v, got=%v", tc.expectVulnerability, hasVulnerability)
			}
			if hasRisk != tc.expectRisk {
				t.Errorf("Expected risk metric present=%v, got=%v", tc.expectRisk, hasRisk)
			}
			if hasExploited != tc.expectExploited {
				t.Errorf("Expected exploited metric present=%v, got=%v", tc.expectExploited, hasExploited)
			}
		})
	}
}

func TestNodeCollector_NilDatabase(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test"

	config := NodeCollectorConfig{
		NodeScannedEnabled:              true,
		NodeVulnerabilitiesEnabled:      true,
		NodeVulnerabilityRiskEnabled:    true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	// Pass nil database
	collector := NewNodeCollector(deploymentUUID, deploymentName, nil, config)
	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Should have no metrics when database is nil
	if strings.Contains(metrics, "bjorn2scan_node_scanned") {
		t.Error("Should not have node scanned metric with nil database")
	}
	if strings.Contains(metrics, "bjorn2scan_node_vulnerability") {
		t.Error("Should not have node vulnerability metric with nil database")
	}
}

func TestNodeCollector_EscapesLabels(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test"

	mockDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name:          "node-with\"quotes",
					Hostname:      "host\\with\\backslash",
					OSRelease:     "OS\"with\"special",
					KernelVersion: "5.15.0",
					Architecture:  "amd64",
				},
			},
		},
	}

	config := NodeCollectorConfig{
		NodeScannedEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify escaped quotes
	if !strings.Contains(metrics, `node="node-with\"quotes"`) {
		t.Error("Expected escaped quotes in node name")
	}
	if !strings.Contains(metrics, `hostname="host\\with\\backslash"`) {
		t.Error("Expected escaped backslashes in hostname")
	}
	if !strings.Contains(metrics, `os_release="OS\"with\"special"`) {
		t.Error("Expected escaped quotes in OS release")
	}
}

func TestNodeCollector_EmptyResults(t *testing.T) {
	deploymentUUID := "test-uuid"
	deploymentName := "test"

	mockDB := &MockNodeDatabaseProvider{
		scannedNodes:    []nodes.NodeWithStatus{},
		vulnerabilities: []database.NodeVulnerabilityForMetrics{},
	}

	config := NodeCollectorConfig{
		NodeScannedEnabled:              true,
		NodeVulnerabilitiesEnabled:      true,
		NodeVulnerabilityRiskEnabled:    true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Should have metric families even if empty
	if len(data.Families) != 4 {
		t.Errorf("Expected 4 metric families, got %d", len(data.Families))
	}

	// Verify each family has correct name but empty metrics
	familyNames := map[string]bool{
		"bjorn2scan_node_scanned":               false,
		"bjorn2scan_node_vulnerability":         false,
		"bjorn2scan_node_vulnerability_risk":    false,
		"bjorn2scan_node_vulnerability_exploited": false,
	}

	for _, family := range data.Families {
		if _, ok := familyNames[family.Name]; ok {
			familyNames[family.Name] = true
			if len(family.Metrics) != 0 {
				t.Errorf("Expected 0 metrics for %s, got %d", family.Name, len(family.Metrics))
			}
		}
	}

	for name, found := range familyNames {
		if !found {
			t.Errorf("Expected metric family %s to be present", name)
		}
	}
}

func TestNodeCollector_VulnerabilityLabelsComplete(t *testing.T) {
	deploymentUUID := "prod-uuid"
	deploymentName := "production"

	mockDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "prod-node-1",
				Hostname:       "prod-node-1.example.com",
				OSRelease:      "Ubuntu 22.04.3 LTS",
				KernelVersion:  "5.15.0-91-generic",
				Architecture:   "amd64",
				VulnID:         42,
				CVEID:          "CVE-2024-9999",
				Severity:       "Critical",
				Score:          10.0,
				FixStatus:      "fixed",
				FixVersion:     "2.0.0",
				KnownExploited: 0,
				PackageName:    "critical-lib",
				PackageVersion: "1.0.0",
				PackageType:    "deb",
				Count:          1,
			},
		},
	}

	config := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	collector := NewNodeCollector(deploymentUUID, deploymentName, mockDB, config)

	data, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	metrics := FormatPrometheus(data)

	// Verify all labels per plan spec
	expectedLabels := []string{
		`deployment_uuid="prod-uuid"`,
		`deployment_name="production"`,
		`node="prod-node-1"`,
		`hostname="prod-node-1.example.com"`,
		`os_release="Ubuntu 22.04.3 LTS"`,
		`kernel_version="5.15.0-91-generic"`,
		`architecture="amd64"`,
		`instance_type="NODE"`,
		`severity="Critical"`,
		`vulnerability="CVE-2024-9999"`,
		`vulnerability_id="prod-uuid.42"`,
		`package_name="critical-lib"`,
		`package_version="1.0.0"`,
		`package_type="deb"`,
		`fix_status="fixed"`,
		`fixed_version="2.0.0"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(metrics, label) {
			t.Errorf("Expected label %s to be present in metrics", label)
		}
	}
}
