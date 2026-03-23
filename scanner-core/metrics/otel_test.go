package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// makeTestOTELExporter creates an OTELExporter for testing.
// provider may be nil if the test does not exercise data collection paths.
// Marks the test as slow because Shutdown() blocks while the OTEL SDK tries to flush.
func makeTestOTELExporter(t *testing.T, provider *MockStreamingProvider, cfg OTELConfig, config UnifiedConfig) *OTELExporter {
	t.Helper()
	if testing.Short() {
		t.Skip("slow: requires OTEL endpoint flush timeout")
	}
	ctx := context.Background()
	info := &MockInfoProvider{deploymentName: "test-cluster", deploymentType: "kubernetes", version: "1.0.0"}

	var staleness *StalenessStore
	if provider != nil {
		staleness = newTestStalenessStore(provider)
	} else {
		staleness = NewStalenessStore(&mockStalenessDB{}, time.Hour)
	}

	var sp StreamingProvider
	if provider != nil {
		sp = provider
	}

	e, err := NewOTELExporter(ctx, info, "test-uuid", sp, config, cfg, staleness)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}
	return e
}

func defaultOTELConfig() OTELConfig {
	return OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}
}

func TestCreateExporter_GRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: OTEL exporter shutdown blocks on gRPC timeout")
	}
	ctx := context.Background()
	exporter, err := createExporter(ctx, OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC exporter: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}
	_ = exporter.Shutdown(ctx)
}

func TestCreateExporter_HTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: OTEL exporter shutdown blocks on HTTP timeout")
	}
	ctx := context.Background()
	exporter, err := createExporter(ctx, OTELConfig{
		Endpoint:     "localhost:9090",
		Protocol:     OTELProtocolHTTP,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("Failed to create HTTP exporter: %v", err)
	}
	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}
	_ = exporter.Shutdown(ctx)
}

func TestCreateExporter_InvalidProtocol(t *testing.T) {
	ctx := context.Background()
	exporter, err := createExporter(ctx, OTELConfig{
		Endpoint: "localhost:4317",
		Protocol: OTELProtocol("invalid"),
	})
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if exporter != nil {
		t.Fatal("Expected nil exporter for invalid protocol")
	}
	if !strings.Contains(err.Error(), "unsupported OTLP protocol") {
		t.Errorf("Expected error to contain 'unsupported OTLP protocol', got %q", err.Error())
	}
}

func TestCreateExporter_ProtocolCaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: OTEL exporter shutdown blocks on network timeout")
	}
	tests := []struct {
		name     string
		protocol string
		wantErr  bool
	}{
		{"grpc lowercase", "grpc", false},
		{"GRPC uppercase", "GRPC", false},
		{"http lowercase", "http", false},
		{"HTTP uppercase", "HTTP", false},
		{"invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			exporter, err := createExporter(ctx, OTELConfig{
				Endpoint:     "localhost:4317",
				Protocol:     OTELProtocol(tt.protocol),
				PushInterval: 1 * time.Minute,
				Insecure:     true,
			})
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for protocol %q", tt.protocol)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for protocol %q: %v", tt.protocol, err)
				}
				if exporter != nil {
					_ = exporter.Shutdown(ctx)
				}
			}
		})
	}
}

func TestNewOTELExporter_Success(t *testing.T) {
	e := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{DeploymentEnabled: true})
	defer func() { _ = e.Shutdown() }()

	if e.meterProvider == nil {
		t.Error("Expected non-nil meterProvider")
	}
	if e.gauges == nil {
		t.Error("Expected non-nil gauges map")
	}
	if e.ctx == nil {
		t.Error("Expected non-nil context")
	}
	if e.cancel == nil {
		t.Error("Expected non-nil cancel function")
	}
}

func TestNewOTELExporter_WithHTTPProtocol(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "prometheus:9090",
		Protocol:     OTELProtocolHTTP,
		PushInterval: 30 * time.Second,
		Insecure:     true,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	if e.config.Protocol != OTELProtocolHTTP {
		t.Errorf("Expected HTTP protocol, got %v", e.config.Protocol)
	}
	if e.config.Endpoint != "prometheus:9090" {
		t.Errorf("Expected prometheus:9090, got %v", e.config.Endpoint)
	}
}

func TestRecordMetrics_NilProvider(t *testing.T) {
	e := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{DeploymentEnabled: true})
	defer func() { _ = e.Shutdown() }()

	// recordMetrics with nil provider should not panic (guards against nil checks)
	e.recordMetrics()
}

func TestRecordMetrics_WithProvider(t *testing.T) {
	provider := newMockStreamingProvider()
	config := UnifiedConfig{
		DeploymentEnabled:        true,
		ScannedContainersEnabled: true,
		NodeScannedEnabled:       true,
	}
	e := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()
	e.recordMetrics()

	// After recording, at least the deployment gauge should have been created
	if len(e.gauges) == 0 {
		t.Error("Expected gauges to be created after recording metrics")
	}
}

func TestShutdown_GracefulShutdown(t *testing.T) {
	e := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{})
	_ = e.Shutdown()

	select {
	case <-e.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled after shutdown")
	}
}

func TestShutdown_MultipleShutdowns(t *testing.T) {
	e := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{})
	_ = e.Shutdown()
	_ = e.Shutdown() // second shutdown should not panic
}

func TestStart_StartsBackgroundPush(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 100 * time.Millisecond,
		Insecure:     true,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	e.Start()
	time.Sleep(250 * time.Millisecond)
	// If we got here without deadlock or panic, the test passes
}

func TestStart_StopsOnShutdown(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 50 * time.Millisecond,
		Insecure:     true,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	e.Start()
	time.Sleep(100 * time.Millisecond)
	_ = e.Shutdown()
	time.Sleep(100 * time.Millisecond)

	select {
	case <-e.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled after shutdown")
	}
}

func TestOTELProtocolConstants(t *testing.T) {
	if OTELProtocolGRPC != "grpc" {
		t.Errorf("Expected OTELProtocolGRPC='grpc', got %q", OTELProtocolGRPC)
	}
	if OTELProtocolHTTP != "http" {
		t.Errorf("Expected OTELProtocolHTTP='http', got %q", OTELProtocolHTTP)
	}
}

func TestOTELConfig_AllFields(t *testing.T) {
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
		t.Errorf("Expected 5m, got %v", config.PushInterval)
	}
	if config.Insecure {
		t.Error("Expected insecure=false")
	}
}

func TestOTELExporter_WithDirectExport(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: true,
		DirectBatchSize: 1000,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	if e.directExporter == nil {
		t.Error("Expected directExporter to be set when UseDirectExport=true")
	}
	if e.infoProvider == nil {
		t.Error("Expected infoProvider to be set")
	}
	if e.deploymentUUID != "test-uuid" {
		t.Errorf("Expected deploymentUUID='test-uuid', got %q", e.deploymentUUID)
	}
}

func TestOTELExporter_WithoutDirectExport(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: false,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	if e.directExporter != nil {
		t.Error("Expected directExporter=nil when UseDirectExport=false")
	}
}

func TestOTELExporter_DirectExportShutdown(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:        "localhost:4317",
		Protocol:        OTELProtocolGRPC,
		PushInterval:    1 * time.Minute,
		Insecure:        true,
		UseDirectExport: true,
		DirectBatchSize: 5000,
	}
	e := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})

	_ = e.Shutdown()
	_ = e.Shutdown() // multiple shutdowns should be safe
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
		t.Error("Expected UseDirectExport=true")
	}
	if config.DirectBatchSize != 10000 {
		t.Errorf("Expected DirectBatchSize=10000, got %d", config.DirectBatchSize)
	}
}

func TestOTELExporter_RecordMetrics_WithNodeData(t *testing.T) {
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{Node: nodes.Node{Name: "node-1", Hostname: "node-1.local", Architecture: "amd64"}},
	}
	config := UnifiedConfig{
		DeploymentEnabled:  true,
		NodeScannedEnabled: true,
	}
	e := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	if len(e.gauges) == 0 {
		t.Error("Expected gauges to be created after recording metrics")
	}
}
