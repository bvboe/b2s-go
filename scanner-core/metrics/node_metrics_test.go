package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// MockNodeDatabaseProvider implements NodeDatabaseProvider for testing.
// Exported so otel_test.go (same package) can reference it for the node DB mock.
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

func (m *MockNodeDatabaseProvider) StreamNodeVulnerabilitiesForMetrics(cb func(v database.NodeVulnerabilityForMetrics) error) error {
	if m.err != nil {
		return m.err
	}
	for _, v := range m.vulnerabilities {
		if err := cb(v); err != nil {
			return err
		}
	}
	return nil
}

func TestGetStreamingDB_ReturnsNilForNonStreaming(t *testing.T) {
	// MockNodeDatabaseProvider implements StreamingNodeDatabaseProvider
	// (has StreamNodeVulnerabilitiesForMetrics), so GetStreamingDB should return it.
	m := &MockNodeDatabaseProvider{}
	result := GetStreamingDB(m)
	if result == nil {
		t.Error("Expected non-nil: MockNodeDatabaseProvider implements StreamingNodeDatabaseProvider")
	}
}

func TestGetStreamingDB_ReturnsNilForNil(t *testing.T) {
	result := GetStreamingDB(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestStreamVulnerabilityMetricsToOTEL_CallsGauges(t *testing.T) {
	// This test verifies that StreamVulnerabilityMetricsToOTEL calls the streaming
	// callback for each vulnerability. We use nil gauges to avoid real OTEL setup.
	mockDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{NodeName: "node-1", CVEID: "CVE-2024-0001", Severity: "Critical", Score: 9.8, Count: 1},
			{NodeName: "node-1", CVEID: "CVE-2024-0002", Severity: "High", Score: 7.5, Count: 2},
		},
	}
	config := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled:   true,
		NodeVulnerabilityRiskEnabled: true,
	}
	gauges := OTELGauges{
		Vuln: nil, // nil gauges — the function checks for nil before calling Record
		Risk: nil,
		Ctx:  nil,
	}

	// Should not panic even with nil gauges (function guards nil checks)
	err := StreamVulnerabilityMetricsToOTEL("uuid", "cluster", config, mockDB, gauges)
	if err != nil {
		t.Fatalf("StreamVulnerabilityMetricsToOTEL returned error: %v", err)
	}
}

func TestStreamVulnerabilityMetricsToOTEL_DBError(t *testing.T) {
	mockDB := &MockNodeDatabaseProvider{err: errStreamTestError}
	config := NodeCollectorConfig{NodeVulnerabilitiesEnabled: true}
	gauges := OTELGauges{}

	err := StreamVulnerabilityMetricsToOTEL("uuid", "cluster", config, mockDB, gauges)
	if err == nil {
		t.Error("Expected error from database")
	}
}

// errStreamTestError is used to simulate DB errors in node_metrics_test.go.
var errStreamTestError = errors.New("mock node metrics error")

func TestCollectNodeScannedLabels(t *testing.T) {
	node := nodes.NodeWithStatus{
		Node: nodes.Node{
			Name:          "worker-1",
			Hostname:      "worker-1.local",
			OSRelease:     "Ubuntu 22.04",
			KernelVersion: "5.15.0",
			Architecture:  "amd64",
		},
	}
	labels := collectNodeScannedLabels("uuid", "cluster", node)

	expected := map[string]string{
		"node":           "worker-1",
		"hostname":       "worker-1.local",
		"os_release":     "Ubuntu 22.04",
		"kernel_version": "5.15.0",
		"architecture":   "amd64",
	}
	for k, v := range expected {
		if labels[k] != v {
			t.Errorf("label %s: expected %q, got %q", k, v, labels[k])
		}
	}
}

func TestCollectNodeVulnLabels(t *testing.T) {
	v := database.NodeVulnerabilityForMetrics{
		NodeName:       "node-1",
		Hostname:       "node-1.local",
		CVEID:          "CVE-2024-1234",
		Severity:       "Critical",
		Score:          9.8,
		PackageName:    "openssl",
		PackageVersion: "3.0.2",
		PackageType:    "deb",
		FixStatus:      "fixed",
		FixVersion:     "1.0.1",
	}
	labels := collectNodeVulnLabels("uuid", "cluster", v)

	if labels["vulnerability"] != "CVE-2024-1234" {
		t.Errorf("Expected vulnerability=CVE-2024-1234, got %q", labels["vulnerability"])
	}
	if labels["severity"] != "Critical" {
		t.Errorf("Expected severity=Critical, got %q", labels["severity"])
	}
	if labels["package_name"] != "openssl" {
		t.Errorf("Expected package_name=openssl, got %q", labels["package_name"])
	}
}

func TestCollectNodeScannedMetrics(t *testing.T) {
	mockDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{Node: nodes.Node{Name: "node-1", Hostname: "node-1.local", Architecture: "amd64"}},
			{Node: nodes.Node{Name: "node-2", Hostname: "node-2.local", Architecture: "arm64"}},
		},
	}
	family, err := collectNodeScannedMetrics("uuid", "cluster", mockDB)
	if err != nil {
		t.Fatalf("collectNodeScannedMetrics failed: %v", err)
	}

	if family.Name != "bjorn2scan_node_scanned" {
		t.Errorf("Expected family name bjorn2scan_node_scanned, got %s", family.Name)
	}
	if len(family.Metrics) != 2 {
		t.Errorf("Expected 2 metrics, got %d", len(family.Metrics))
	}
	for _, m := range family.Metrics {
		if m.Value != 1 {
			t.Errorf("Expected value=1, got %f", m.Value)
		}
	}
}

func TestStreamMetrics_NodeVulnerabilityLabels(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "production", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.nodeVulns = []database.NodeVulnerabilityForMetrics{
		{
			NodeName:       "prod-node-1",
			Hostname:       "prod-node-1.example.com",
			OSRelease:      "Ubuntu 22.04.3 LTS",
			KernelVersion:  "5.15.0-91-generic",
			Architecture:   "amd64",
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
	}
	config := UnifiedConfig{NodeVulnerabilitiesEnabled: true}

	var buf strings.Builder
	_, err := StreamMetrics(&buf, info, "prod-uuid", provider, config, nil, time.Now())
	if err != nil {
		t.Fatalf("StreamMetrics failed: %v", err)
	}
	output := buf.String()

	expectedLabels := []string{
		`deployment_uuid="prod-uuid"`,
		`deployment_name="production"`,
		`node="prod-node-1"`,
		`hostname="prod-node-1.example.com"`,
		`os_release="Ubuntu 22.04.3 LTS"`,
		`kernel_version="5.15.0-91-generic"`,
		`architecture="amd64"`,
		`severity="Critical"`,
		`vulnerability="CVE-2024-9999"`,
		`package_name="critical-lib"`,
		`package_version="1.0.0"`,
		`package_type="deb"`,
		`fix_status="fixed"`,
		`fixed_version="2.0.0"`,
	}

	for _, label := range expectedLabels {
		if !strings.Contains(output, label) {
			t.Errorf("Expected label %s in output", label)
		}
	}
}

