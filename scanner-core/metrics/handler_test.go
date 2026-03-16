package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// mockInfoProvider implements InfoProvider for testing
type mockInfoProvider struct {
	deploymentName string
	deploymentType string
	version        string
}

func (m *mockInfoProvider) GetDeploymentName() string { return m.deploymentName }
func (m *mockInfoProvider) GetDeploymentType() string { return m.deploymentType }
func (m *mockInfoProvider) GetVersion() string        { return m.version }
func (m *mockInfoProvider) GetDeploymentIP() string   { return "192.168.1.1" }
func (m *mockInfoProvider) GetConsoleURL() string     { return "http://localhost:9999/" }
func (m *mockInfoProvider) GetGrypeDBBuilt() string   { return "" }

// mockDatabaseProvider implements DatabaseProvider for testing
type mockDatabaseProvider struct{}

func (m *mockDatabaseProvider) GetScannedContainers() ([]database.ScannedContainer, error) {
	return []database.ScannedContainer{}, nil
}

func (m *mockDatabaseProvider) GetContainerVulnerabilities() ([]database.ContainerVulnerability, error) {
	return []database.ContainerVulnerability{}, nil
}

func (m *mockDatabaseProvider) GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error) {
	return []database.ImageScanStatusCount{}, nil
}

// mockNodeDatabaseForHandler implements NodeDatabaseProvider for testing
type mockNodeDatabaseForHandler struct {
	scannedNodes    []nodes.NodeWithStatus
	vulnerabilities []database.NodeVulnerabilityForMetrics
}

func (m *mockNodeDatabaseForHandler) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	return m.scannedNodes, nil
}

func (m *mockNodeDatabaseForHandler) GetNodeVulnerabilitiesForMetrics() ([]database.NodeVulnerabilityForMetrics, error) {
	return m.vulnerabilities, nil
}

func TestHandlerWithNodes_ReturnsMetrics(t *testing.T) {
	infoProvider := &mockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	imageDB := &mockDatabaseProvider{}

	nodeDB := &mockNodeDatabaseForHandler{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name:          "node-1",
					Hostname:      "node-1.local",
					OSRelease:     "Ubuntu 22.04",
					KernelVersion: "5.15.0",
					Architecture:  "amd64",
				},
			},
		},
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				Hostname:       "node-1.local",
				OSRelease:      "Ubuntu 22.04",
				KernelVersion:  "5.15.0",
				Architecture:   "amd64",
				VulnID:         1,
				CVEID:          "CVE-2024-1234",
				Severity:       "Critical",
				Score:          9.8,
				FixStatus:      "fixed",
				FixVersion:     "1.0.1",
				KnownExploited: 1,
				PackageName:    "openssl",
				PackageVersion: "3.0.2",
				PackageType:    "deb",
				Count:          1,
			},
		},
	}

	imageConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	nodeConfig := NodeCollectorConfig{
		NodeScannedEnabled:              true,
		NodeVulnerabilitiesEnabled:      true,
		NodeVulnerabilityRiskEnabled:    true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	handler := HandlerWithNodes(infoProvider, "test-uuid", imageDB, imageConfig, nodeDB, nodeConfig, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	// Verify node scanned metric is present
	if !strings.Contains(body, "bjorn2scan_node_scanned{") {
		t.Error("Expected bjorn2scan_node_scanned metric")
	}

	// Verify node vulnerability metrics are present
	if !strings.Contains(body, "bjorn2scan_node_vulnerability{") {
		t.Error("Expected bjorn2scan_node_vulnerability metric")
	}

	if !strings.Contains(body, "bjorn2scan_node_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_node_vulnerability_risk metric")
	}

	if !strings.Contains(body, "bjorn2scan_node_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_node_vulnerability_exploited metric")
	}

	// Verify labels are present
	if !strings.Contains(body, `node="node-1"`) {
		t.Error("Expected node label")
	}

	if !strings.Contains(body, `vulnerability="CVE-2024-1234"`) {
		t.Error("Expected vulnerability label")
	}
}

func TestHandlerWithNodes_NilNodeDatabase(t *testing.T) {
	infoProvider := &mockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	imageDB := &mockDatabaseProvider{}

	imageConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	nodeConfig := NodeCollectorConfig{
		NodeScannedEnabled: true,
	}

	// Pass nil node database
	handler := HandlerWithNodes(infoProvider, "test-uuid", imageDB, imageConfig, nil, nodeConfig, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 even with nil node database, got %d", resp.StatusCode)
	}

	body := w.Body.String()

	// Should have image metrics but not node metrics
	if !strings.Contains(body, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}

	if strings.Contains(body, "bjorn2scan_node_scanned{") {
		t.Error("Should not have node metrics when node database is nil")
	}
}

func TestHandlerWithNodes_MethodNotAllowed(t *testing.T) {
	infoProvider := &mockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	imageDB := &mockDatabaseProvider{}
	nodeDB := &mockNodeDatabaseForHandler{}

	imageConfig := CollectorConfig{}
	nodeConfig := NodeCollectorConfig{}

	handler := HandlerWithNodes(infoProvider, "test-uuid", imageDB, imageConfig, nodeDB, nodeConfig, nil)

	// Test POST method
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 for POST, got %d", resp.StatusCode)
	}
}

func TestHandlerWithNodes_DisabledNodeMetrics(t *testing.T) {
	infoProvider := &mockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}

	imageDB := &mockDatabaseProvider{}

	nodeDB := &mockNodeDatabaseForHandler{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name: "node-1",
				},
			},
		},
	}

	imageConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	// All node metrics disabled
	nodeConfig := NodeCollectorConfig{
		NodeScannedEnabled:              false,
		NodeVulnerabilitiesEnabled:      false,
		NodeVulnerabilityRiskEnabled:    false,
		NodeVulnerabilityExploitedEnabled: false,
	}

	handler := HandlerWithNodes(infoProvider, "test-uuid", imageDB, imageConfig, nodeDB, nodeConfig, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	body := w.Body.String()

	// Should not have any node metrics when all are disabled
	if strings.Contains(body, "bjorn2scan_node_") {
		t.Error("Should not have node metrics when all are disabled")
	}
}
