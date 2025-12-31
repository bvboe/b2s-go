package metrics

import (
	"strings"
	"testing"
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

func TestCollector_Collect(t *testing.T) {
	infoProvider := &MockInfoProvider{
		deploymentName: "test-host",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	collector := NewCollector(infoProvider, deploymentUUID)

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

	collector := NewCollector(infoProvider, deploymentUUID)
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

	collector := NewCollector(infoProvider, deploymentUUID)
	metrics, err := collector.Collect()
	if err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify escaped quotes
	if !strings.Contains(metrics, `deployment_name="host\"with\"quotes"`) {
		t.Error("Expected escaped quotes in deployment_name")
	}
}
