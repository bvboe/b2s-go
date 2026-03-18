package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

var errMockError = errors.New("mock database error")

func TestCreateExporter_GRPC(t *testing.T) {
	ctx := context.Background()
	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := createExporter(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create gRPC exporter: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Cleanup
	_ = exporter.Shutdown(ctx)
}

func TestCreateExporter_HTTP(t *testing.T) {
	ctx := context.Background()
	config := OTELConfig{
		Endpoint:     "localhost:9090",
		Protocol:     OTELProtocolHTTP,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := createExporter(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create HTTP exporter: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Cleanup
	_ = exporter.Shutdown(ctx)
}

func TestCreateExporter_InvalidProtocol(t *testing.T) {
	ctx := context.Background()
	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocol("invalid"),
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := createExporter(ctx, config)
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if exporter != nil {
		t.Fatal("Expected nil exporter for invalid protocol")
	}

	expectedError := "unsupported OTLP protocol: invalid"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestCreateExporter_ProtocolCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		wantErr  bool
	}{
		{"grpc lowercase", "grpc", false},
		{"GRPC uppercase", "GRPC", false},
		{"GrPc mixed case", "GrPc", false},
		{"http lowercase", "http", false},
		{"HTTP uppercase", "HTTP", false},
		{"HtTp mixed case", "HtTp", false},
		{"invalid protocol", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := OTELConfig{
				Endpoint:     "localhost:4317",
				Protocol:     OTELProtocol(tt.protocol),
				PushInterval: 1 * time.Minute,
				Insecure:     true,
			}

			exporter, err := createExporter(ctx, config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for protocol %q", tt.protocol)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for protocol %q: %v", tt.protocol, err)
				}
				if exporter == nil {
					t.Errorf("Expected non-nil exporter for protocol %q", tt.protocol)
				} else {
					_ = exporter.Shutdown(ctx)
				}
			}
		})
	}
}

func TestNewOTELExporter_Success(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test-deployment",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Verify fields are set correctly
	if exporter.collector == nil {
		t.Error("Expected non-nil collector")
	}
	if exporter.meterProvider == nil {
		t.Error("Expected non-nil meter provider")
	}
	if exporter.gauges == nil {
		t.Error("Expected non-nil gauges map")
	}
	if exporter.ctx == nil {
		t.Error("Expected non-nil context")
	}
	if exporter.cancel == nil {
		t.Error("Expected non-nil cancel function")
	}

	// Cleanup - shutdown may fail to flush metrics if no receiver is running (expected in tests)
	_ = exporter.Shutdown()
}

func TestNewOTELExporter_WithHTTPProtocol(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "k8s-cluster",
		deploymentType: "kubernetes",
		version:        "2.0.0",
	}
	deploymentUUID := "abc-123-def-456"
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "prometheus:9090",
		Protocol:     OTELProtocolHTTP,
		PushInterval: 30 * time.Second,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter with HTTP: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Verify config is preserved
	if exporter.config.Protocol != OTELProtocolHTTP {
		t.Errorf("Expected HTTP protocol, got %v", exporter.config.Protocol)
	}
	if exporter.config.Endpoint != "prometheus:9090" {
		t.Errorf("Expected prometheus:9090, got %v", exporter.config.Endpoint)
	}

	// Cleanup - shutdown may fail to flush metrics if no receiver is running (expected in tests)
	_ = exporter.Shutdown()
}

func TestRecordMetrics(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test-host",
		deploymentType: "agent",
		version:        "1.5.0",
	}
	deploymentUUID := "test-uuid-123"
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Call recordMetrics - should not panic or error
	exporter.recordMetrics()

	// If we got here without panic, the test passes
	// We can't easily verify the metrics were recorded without a mock receiver,
	// but we've confirmed the code path executes successfully
}

func TestShutdown_GracefulShutdown(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}

	// Shutdown completes (may return error if no receiver is running, which is expected in tests)
	_ = exporter.Shutdown()

	// Context should be cancelled
	select {
	case <-exporter.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled after shutdown")
	}
}

func TestShutdown_MultipleShutdowns(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}

	// First shutdown (may fail if no receiver, which is expected in tests)
	_ = exporter.Shutdown()

	// Second shutdown should handle being called again without panicking
	_ = exporter.Shutdown()
	// Multiple shutdowns should be safe even if they return errors
}

func TestStart_StartsBackgroundPush(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 100 * time.Millisecond, // Short interval for testing
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Start the exporter
	exporter.Start()

	// Wait for at least one push cycle to complete
	time.Sleep(250 * time.Millisecond)

	// If we got here without deadlock or panic, the test passes
	// The background goroutine is running and pushing metrics
}

func TestStart_StopsOnShutdown(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 50 * time.Millisecond,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}

	// Start the background push
	exporter.Start()

	// Let it run for a bit
	time.Sleep(100 * time.Millisecond)

	// Shutdown should stop the background goroutine (may fail to flush if no receiver)
	_ = exporter.Shutdown()

	// Wait a bit to ensure goroutine exits
	time.Sleep(100 * time.Millisecond)

	// Context should be done
	select {
	case <-exporter.ctx.Done():
		// Expected - background goroutine should have exited
	default:
		t.Error("Expected context to be cancelled")
	}
}

func TestOTELProtocolConstants(t *testing.T) {
	// Verify protocol constants have expected values
	if OTELProtocolGRPC != "grpc" {
		t.Errorf("Expected OTELProtocolGRPC to be 'grpc', got %q", OTELProtocolGRPC)
	}
	if OTELProtocolHTTP != "http" {
		t.Errorf("Expected OTELProtocolHTTP to be 'http', got %q", OTELProtocolHTTP)
	}
}

func TestOTELConfig_AllFields(t *testing.T) {
	// Test that OTELConfig struct can be instantiated with all fields
	config := OTELConfig{
		Endpoint:     "test:1234",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 5 * time.Minute,
		Insecure:     false,
	}

	if config.Endpoint != "test:1234" {
		t.Errorf("Expected endpoint 'test:1234', got %q", config.Endpoint)
	}
	if config.Protocol != OTELProtocolGRPC {
		t.Errorf("Expected protocol 'grpc', got %q", config.Protocol)
	}
	if config.PushInterval != 5*time.Minute {
		t.Errorf("Expected push interval 5m, got %v", config.PushInterval)
	}
	if config.Insecure != false {
		t.Errorf("Expected insecure false, got %v", config.Insecure)
	}
}

func TestOTELExporter_RecordScannedContainers(t *testing.T) {
	ctx := context.Background()
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

	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: true,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, mockDB, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Verify gauges map was created
	if exporter.gauges == nil {
		t.Error("Expected non-nil gauges map")
	}

	// Call recordMetrics - should not panic and should record both metrics
	exporter.recordMetrics()

	// If we got here without panic, the test passes
	// We've confirmed the code path executes successfully with scanned containers enabled
}

func TestOTELExporter_ScannedContainersDisabled(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Name:  "test",
				NodeName:   "node-1",
				Reference: "test:latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedContainersEnabled: false, // Disabled
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", mockDB, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Verify gauges map was created (gauges are created dynamically on demand)
	if exporter.gauges == nil {
		t.Error("Expected non-nil gauges map")
	}

	// Call recordMetrics - should not panic even with scanned containers disabled
	exporter.recordMetrics()

	// If we got here without panic, the test passes
}

func TestOTELExporter_SetNodeCollector(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "550e8400-e29b-41d4-a716-446655440000"

	collectorConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Initially nodeCollector should be nil
	if exporter.nodeCollector != nil {
		t.Error("Expected nodeCollector to be nil initially")
	}

	// Create a node collector with mock data
	mockNodeDB := &MockNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName: "node-1",
				CVEID:    "CVE-2024-1234",
				Severity: "Critical",
				Score:    9.8,
				Count:    1,
			},
		},
	}

	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	nodeCollector := NewNodeCollector(deploymentUUID, "test-cluster", mockNodeDB, nodeConfig)

	// Set the node collector
	exporter.SetNodeCollector(nodeCollector)

	// Verify nodeCollector is set
	if exporter.nodeCollector == nil {
		t.Error("Expected nodeCollector to be set after SetNodeCollector")
	}

	// Call recordMetrics - should include node metrics without panic
	exporter.recordMetrics()

	// If we got here without panic, the test passes
}

func TestOTELExporter_RecordMetricsWithNodeCollector(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "prod-cluster",
		deploymentType: "kubernetes",
		version:        "2.0.0",
	}
	deploymentUUID := "prod-uuid-123"

	// Mock image database
	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainer{
			{
				Namespace:  "default",
				Pod:        "app-pod",
				Name:       "app",
				NodeName:   "node-1",
				Reference:  "app:v1",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
	}

	// Mock node database
	mockNodeDB := &MockNodeDatabaseProvider{
		scannedNodes: []nodes.NodeWithStatus{
			{
				Node: nodes.Node{
					Name:         "node-1",
					Hostname:     "node-1.local",
					OSRelease:    "Ubuntu 22.04",
					Architecture: "amd64",
				},
			},
		},
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{
				NodeName:       "node-1",
				CVEID:          "CVE-2024-5678",
				Severity:       "High",
				Score:          7.5,
				KnownExploited: 1,
				Count:          2,
			},
		},
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled:        true,
		ScannedContainersEnabled: true,
	}

	nodeConfig := NodeCollectorConfig{
		NodeScannedEnabled:                true,
		NodeVulnerabilitiesEnabled:        true,
		NodeVulnerabilityRiskEnabled:      true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, mockDB, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Set node collector
	nodeCollector := NewNodeCollector(deploymentUUID, "prod-cluster", mockNodeDB, nodeConfig)
	exporter.SetNodeCollector(nodeCollector)

	// Call recordMetrics multiple times - should handle both image and node metrics
	exporter.recordMetrics()
	exporter.recordMetrics()

	// Verify gauges were created for both image and node metrics
	// The exact gauge names depend on what metrics are enabled
	if len(exporter.gauges) == 0 {
		t.Error("Expected gauges to be created after recording metrics")
	}
}

func TestOTELExporter_NodeCollectorError(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	config := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Create a node collector that will return an error
	mockNodeDB := &MockNodeDatabaseProvider{
		err: errMockError,
	}

	nodeConfig := NodeCollectorConfig{
		NodeScannedEnabled: true,
	}

	nodeCollector := NewNodeCollector("test-uuid", "test", mockNodeDB, nodeConfig)
	exporter.SetNodeCollector(nodeCollector)

	// Call recordMetrics - should handle node collector error gracefully without panic
	exporter.recordMetrics()

	// If we got here without panic, the test passes - errors are logged but don't stop image metrics
}

func TestOTELExporter_WithDirectExport(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test-cluster",
		deploymentType: "kubernetes",
		version:        "1.0.0",
	}
	deploymentUUID := "direct-export-test-uuid"

	collectorConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	config := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: true,
		DirectBatchSize: 1000,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, deploymentUUID, nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Verify direct exporter was created
	if exporter.directExporter == nil {
		t.Error("Expected direct exporter to be initialized when UseDirectExport is true")
	}

	// Verify infoProvider and deploymentUUID are set for direct export
	if exporter.infoProvider == nil {
		t.Error("Expected infoProvider to be set")
	}
	if exporter.deploymentUUID != deploymentUUID {
		t.Errorf("Expected deploymentUUID %q, got %q", deploymentUUID, exporter.deploymentUUID)
	}
}

func TestOTELExporter_WithoutDirectExport(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	config := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: false, // Explicitly disabled
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown() }()

	// Verify direct exporter was NOT created
	if exporter.directExporter != nil {
		t.Error("Expected direct exporter to be nil when UseDirectExport is false")
	}
}

func TestOTELExporter_DirectExportShutdown(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled: true,
	}

	config := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: true,
		DirectBatchSize: 5000,
	}

	exporter, err := NewOTELExporter(ctx, infoProvider, "test-uuid", nil, collectorConfig, config)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}

	// Shutdown should close the direct exporter without errors
	_ = exporter.Shutdown()

	// Multiple shutdowns should be safe
	_ = exporter.Shutdown()
}

func TestOTELConfig_DirectExportFields(t *testing.T) {
	config := OTELConfig{
		Endpoint:        "localhost:9090",
		Protocol:        OTELProtocolHTTP,
		PushInterval:    5 * time.Minute,
		Insecure:        true,
		UseDirectExport: true,
		DirectBatchSize: 10000,
	}

	if !config.UseDirectExport {
		t.Error("Expected UseDirectExport to be true")
	}
	if config.DirectBatchSize != 10000 {
		t.Errorf("Expected DirectBatchSize 10000, got %d", config.DirectBatchSize)
	}
}
