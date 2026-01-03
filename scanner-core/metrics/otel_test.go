package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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
		ScannedInstancesEnabled: false,
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

func TestOTELExporter_RecordScannedInstances(t *testing.T) {
	ctx := context.Background()
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

	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedInstancesEnabled: true,
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
	// We've confirmed the code path executes successfully with scanned instances enabled
}

func TestOTELExporter_ScannedInstancesDisabled(t *testing.T) {
	ctx := context.Background()
	infoProvider := &MockInfoProvider{
		deploymentName: "test",
		deploymentType: "agent",
		version:        "1.0.0",
	}

	mockDB := &MockDatabaseProvider{
		instances: []database.ScannedContainerInstance{
			{
				Namespace:  "default",
				Pod:        "test-pod",
				Container:  "test",
				NodeName:   "node-1",
				Repository: "test",
				Tag:        "latest",
				Digest:     "sha256:abc",
				OSName:     "alpine",
			},
		},
	}

	collectorConfig := CollectorConfig{
		DeploymentEnabled:       true,
		ScannedInstancesEnabled: false, // Disabled
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

	// Call recordMetrics - should not panic even with scanned instances disabled
	exporter.recordMetrics()

	// If we got here without panic, the test passes
}
