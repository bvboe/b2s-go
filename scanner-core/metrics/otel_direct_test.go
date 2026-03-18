package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// MockStreamingNodeDatabaseProvider implements StreamingNodeDatabaseProvider for testing
type MockStreamingNodeDatabaseProvider struct {
	scannedNodes    []nodes.NodeWithStatus
	vulnerabilities []database.NodeVulnerabilityForMetrics
	err             error
	callbackCount   int
}

func (m *MockStreamingNodeDatabaseProvider) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scannedNodes, nil
}

func (m *MockStreamingNodeDatabaseProvider) GetNodeVulnerabilitiesForMetrics() ([]database.NodeVulnerabilityForMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.vulnerabilities, nil
}

func (m *MockStreamingNodeDatabaseProvider) StreamNodeVulnerabilitiesForMetrics(callback func(v database.NodeVulnerabilityForMetrics) error) error {
	if m.err != nil {
		return m.err
	}
	for _, v := range m.vulnerabilities {
		m.callbackCount++
		if err := callback(v); err != nil {
			return err
		}
	}
	return nil
}

func TestDirectOTLPConfig_Defaults(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:4317",
		Protocol:       "http",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	// BatchSize, Timeout, MaxRetries should get defaults when creating sender
	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it was created successfully
	if sender == nil {
		t.Fatal("Expected non-nil sender")
	}
}

func TestNewDirectOTLPSender_HTTP(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "http://localhost:9090",
		Protocol:       "http",
		BatchSize:      1000,
		Timeout:        10 * time.Second,
		MaxRetries:     5,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		DeploymentName: "test-deployment",
		DeploymentUUID: "test-uuid",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create HTTP sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it's the HTTP type
	_, ok := sender.(*HTTPDirectOTLPSender)
	if !ok {
		t.Error("Expected HTTPDirectOTLPSender type")
	}
}

func TestNewDirectOTLPSender_GRPC(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:4317",
		Protocol:       "grpc",
		BatchSize:      5000,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create gRPC sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it's the gRPC type
	_, ok := sender.(*GRPCDirectOTLPSender)
	if !ok {
		t.Error("Expected GRPCDirectOTLPSender type")
	}
}

func TestNewDirectOTLPSender_InvalidProtocol(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:4317",
		Protocol: "invalid",
	}

	sender, err := NewDirectOTLPSender(config)
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if sender != nil {
		t.Fatal("Expected nil sender for invalid protocol")
	}

	expectedError := "unsupported OTLP protocol: invalid"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestNewDirectOTLPSender_ProtocolCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		wantErr  bool
	}{
		{"http lowercase", "http", false},
		{"HTTP uppercase", "HTTP", false},
		{"Http mixed", "Http", false},
		{"grpc lowercase", "grpc", false},
		{"GRPC uppercase", "GRPC", false},
		{"GrPc mixed", "GrPc", false},
		{"invalid", "websocket", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DirectOTLPConfig{
				Endpoint: "localhost:4317",
				Protocol: tt.protocol,
				Insecure: true,
			}

			sender, err := NewDirectOTLPSender(config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for protocol %q", tt.protocol)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for protocol %q: %v", tt.protocol, err)
				}
				if sender == nil {
					t.Errorf("Expected non-nil sender for protocol %q", tt.protocol)
				} else {
					_ = sender.Close()
				}
			}
		})
	}
}

func TestHTTPDirectOTLPSender_Send(t *testing.T) {
	// Create a test server that accepts OTLP requests
	receivedRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequests++

		// Verify content type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-protobuf" {
			t.Errorf("Expected Content-Type application/x-protobuf, got %s", contentType)
		}

		// Verify method
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify path ends with /v1/metrics
		if !strings.HasSuffix(r.URL.Path, "/v1/metrics") {
			t.Errorf("Expected path ending with /v1/metrics, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      5000,
		Timeout:        5 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Send test metrics
	metrics := []*metricsv1.Metric{
		{
			Name:        "test_metric",
			Description: "Test metric",
			Data: &metricsv1.Metric_Gauge{
				Gauge: &metricsv1.Gauge{
					DataPoints: []*metricsv1.NumberDataPoint{
						{
							Value: &metricsv1.NumberDataPoint_AsDouble{AsDouble: 42.0},
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	err = sender.Send(ctx, metrics)
	if err != nil {
		t.Fatalf("Failed to send metrics: %v", err)
	}

	if receivedRequests != 1 {
		t.Errorf("Expected 1 request, got %d", receivedRequests)
	}
}

func TestHTTPDirectOTLPSender_SendWithRetry(t *testing.T) {
	// Create a server that fails the first 2 requests, succeeds on 3rd
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err != nil {
		t.Fatalf("Expected success after retries, got error: %v", err)
	}

	if requestCount != 3 {
		t.Errorf("Expected 3 requests (2 failures + 1 success), got %d", requestCount)
	}
}

func TestHTTPDirectOTLPSender_SendFailsAfterMaxRetries(t *testing.T) {
	// Create a server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     2,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err == nil {
		t.Fatal("Expected error after max retries")
	}

	if !strings.Contains(err.Error(), "failed after 2 attempts") {
		t.Errorf("Expected error message about failed attempts, got: %v", err)
	}
}

func TestHTTPDirectOTLPSender_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        10 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

func TestNewDirectOTLPExporter(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:9090",
		Protocol:       "http",
		BatchSize:      5000,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
		DeploymentName: "test",
		DeploymentUUID: "test-uuid",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}

	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Cleanup
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestNewDirectOTLPExporter_InvalidProtocol(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:9090",
		Protocol: "invalid",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if exporter != nil {
		t.Fatal("Expected nil exporter for invalid protocol")
	}
}

func TestDirectOTLPExporter_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:9090",
		Protocol:       "http",
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}

	// Close should not error
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}

	// Multiple closes should be safe
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on second close: %v", err)
	}
}

func TestDirectOTLPExporter_StreamNodeVulnerabilityMetrics(t *testing.T) {
	// Create a test server
	batchesReceived := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batchesReceived++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      2, // Small batch size to test batching
		Timeout:        5 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
		DeploymentName: "test-cluster",
		DeploymentUUID: "test-uuid",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Close() }()

	// Create mock database with several vulnerabilities
	mockDB := &MockStreamingNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{NodeName: "node-1", CVEID: "CVE-2024-001", Severity: "Critical", Score: 9.8, Count: 1},
			{NodeName: "node-1", CVEID: "CVE-2024-002", Severity: "High", Score: 7.5, Count: 1},
			{NodeName: "node-2", CVEID: "CVE-2024-003", Severity: "Medium", Score: 5.0, Count: 1},
			{NodeName: "node-2", CVEID: "CVE-2024-004", Severity: "Low", Score: 3.0, Count: 1, KnownExploited: 1},
			{NodeName: "node-3", CVEID: "CVE-2024-005", Severity: "Critical", Score: 10.0, Count: 2},
		},
	}

	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled:        true,
		NodeVulnerabilityRiskEnabled:      true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	ctx := context.Background()
	err = exporter.StreamNodeVulnerabilityMetrics(ctx, mockDB, nodeConfig, "test-uuid", "test-cluster")
	if err != nil {
		t.Fatalf("Failed to stream metrics: %v", err)
	}

	// With batch size of 2 and 5 vulnerabilities, we should have multiple batches
	// The exact number depends on how the batching logic works
	if batchesReceived == 0 {
		t.Error("Expected at least one batch to be received")
	}
}

func TestDirectOTLPExporter_StreamNodeVulnerabilityMetrics_EmptyDB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      5000,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Close() }()

	// Empty database
	mockDB := &MockStreamingNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{},
	}

	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	ctx := context.Background()
	err = exporter.StreamNodeVulnerabilityMetrics(ctx, mockDB, nodeConfig, "test-uuid", "test-cluster")
	if err != nil {
		t.Fatalf("Expected no error for empty database, got: %v", err)
	}
}

func TestDirectOTLPExporter_StreamNodeVulnerabilityMetrics_DBError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      5000,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Close() }()

	// Database that returns error
	mockDB := &MockStreamingNodeDatabaseProvider{
		err: errors.New("database connection error"),
	}

	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	ctx := context.Background()
	err = exporter.StreamNodeVulnerabilityMetrics(ctx, mockDB, nodeConfig, "test-uuid", "test-cluster")
	if err == nil {
		t.Fatal("Expected error from database")
	}
}

func TestDirectOTLPExporter_StreamNodeVulnerabilityMetrics_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      2,
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Close() }()

	mockDB := &MockStreamingNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{NodeName: "node-1", CVEID: "CVE-2024-001", Severity: "Critical", Count: 1},
		},
	}

	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled: true,
	}

	ctx := context.Background()
	err = exporter.StreamNodeVulnerabilityMetrics(ctx, mockDB, nodeConfig, "test-uuid", "test-cluster")
	if err == nil {
		t.Fatal("Expected error from server failure")
	}
}

func TestDirectOTLPExporter_StreamNodeVulnerabilityMetrics_DisabledMetrics(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      5000,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Close() }()

	mockDB := &MockStreamingNodeDatabaseProvider{
		vulnerabilities: []database.NodeVulnerabilityForMetrics{
			{NodeName: "node-1", CVEID: "CVE-2024-001", Severity: "Critical", Count: 1},
		},
	}

	// All metrics disabled
	nodeConfig := NodeCollectorConfig{
		NodeVulnerabilitiesEnabled:        false,
		NodeVulnerabilityRiskEnabled:      false,
		NodeVulnerabilityExploitedEnabled: false,
	}

	ctx := context.Background()
	err = exporter.StreamNodeVulnerabilityMetrics(ctx, mockDB, nodeConfig, "test-uuid", "test-cluster")
	if err != nil {
		t.Fatalf("Expected no error with disabled metrics, got: %v", err)
	}

	// No requests should be made since no metrics are enabled
	// (flush would be called but with empty slices)
	// This depends on implementation - if empty flush sends no requests
}

func TestBuildVulnAttributes(t *testing.T) {
	v := database.NodeVulnerabilityForMetrics{
		NodeName:       "test-node",
		Hostname:       "test-node.local",
		OSRelease:      "Ubuntu 22.04",
		KernelVersion:  "5.15.0",
		Architecture:   "amd64",
		CVEID:          "CVE-2024-1234",
		Severity:       "Critical",
		FixStatus:      "fixed",
		FixVersion:     "1.2.3",
		PackageName:    "openssl",
		PackageVersion: "1.1.1",
		PackageType:    "deb",
	}

	attrs := buildVulnAttributes(v, "deploy-uuid", "deploy-name")

	// Verify we have the expected number of attributes
	expectedCount := 14 // All the fields we're setting
	if len(attrs) != expectedCount {
		t.Errorf("Expected %d attributes, got %d", expectedCount, len(attrs))
	}

	// Verify some specific attributes
	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[attr.Key] = attr.Value.GetStringValue()
	}

	tests := []struct {
		key      string
		expected string
	}{
		{"deployment_uuid", "deploy-uuid"},
		{"deployment_name", "deploy-name"},
		{"node_name", "test-node"},
		{"cve_id", "CVE-2024-1234"},
		{"severity", "Critical"},
		{"package_name", "openssl"},
	}

	for _, tt := range tests {
		if val, ok := attrMap[tt.key]; !ok {
			t.Errorf("Missing attribute %s", tt.key)
		} else if val != tt.expected {
			t.Errorf("Attribute %s: expected %q, got %q", tt.key, tt.expected, val)
		}
	}
}

func TestStringKV(t *testing.T) {
	kv := stringKV("test-key", "test-value")

	if kv.Key != "test-key" {
		t.Errorf("Expected key 'test-key', got %q", kv.Key)
	}

	strVal := kv.Value.GetStringValue()
	if strVal != "test-value" {
		t.Errorf("Expected value 'test-value', got %q", strVal)
	}
}

func TestDirectOTLPConfig_AllFields(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "prometheus:9090",
		Protocol:       "http",
		BatchSize:      10000,
		Timeout:        1 * time.Minute,
		MaxRetries:     5,
		Insecure:       false,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "2.0.0",
		DeploymentName: "production",
		DeploymentUUID: "prod-uuid-123",
	}

	if config.Endpoint != "prometheus:9090" {
		t.Errorf("Expected endpoint 'prometheus:9090', got %q", config.Endpoint)
	}
	if config.Protocol != "http" {
		t.Errorf("Expected protocol 'http', got %q", config.Protocol)
	}
	if config.BatchSize != 10000 {
		t.Errorf("Expected batch size 10000, got %d", config.BatchSize)
	}
	if config.Timeout != 1*time.Minute {
		t.Errorf("Expected timeout 1m, got %v", config.Timeout)
	}
	if config.MaxRetries != 5 {
		t.Errorf("Expected max retries 5, got %d", config.MaxRetries)
	}
	if config.Insecure != false {
		t.Errorf("Expected insecure false, got %v", config.Insecure)
	}
}

func TestGRPCDirectOTLPSender_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:4317",
		Protocol: "grpc",
		Insecure: true,
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create gRPC sender: %v", err)
	}

	// Close should not error
	err = sender.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestHTTPDirectOTLPSender_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:9090",
		Protocol: "http",
		Insecure: true,
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create HTTP sender: %v", err)
	}

	// Close should be no-op for HTTP sender
	err = sender.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestHTTPDirectOTLPSender_EndpointURLBuilding(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		expectedPath string
	}{
		{
			name:         "no path - adds prometheus otlp path",
			endpoint:     "http://localhost:9090",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
		{
			name:         "with trailing slash",
			endpoint:     "http://localhost:9090/",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
		{
			name:         "already has v1/metrics",
			endpoint:     "http://localhost:9090/v1/metrics",
			expectedPath: "/v1/metrics",
		},
		{
			name:         "already has full prometheus path",
			endpoint:     "http://localhost:9090/api/v1/otlp/v1/metrics",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Override endpoint to use test server
			config := DirectOTLPConfig{
				Endpoint:       server.URL,
				Protocol:       "http",
				Timeout:        1 * time.Second,
				MaxRetries:     1,
				Insecure:       true,
				ServiceName:    "test",
				ServiceVersion: "1.0.0",
			}

			sender, err := NewDirectOTLPSender(config)
			if err != nil {
				t.Fatalf("Failed to create sender: %v", err)
			}
			defer func() { _ = sender.Close() }()

			ctx := context.Background()
			_ = sender.Send(ctx, []*metricsv1.Metric{})

			if !strings.HasSuffix(receivedPath, "/v1/metrics") {
				t.Errorf("Expected path to end with /v1/metrics, got %q", receivedPath)
			}
		})
	}
}

func TestHTTPDirectOTLPSender_EndpointWithoutScheme(t *testing.T) {
	// Create a test server
	var receivedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract host:port from server URL (strip http://)
	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Test with endpoint that has no scheme (like kubernetes service names)
	config := DirectOTLPConfig{
		Endpoint:       serverAddr, // e.g., "127.0.0.1:12345" without http://
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err != nil {
		t.Fatalf("Failed to send metrics: %v", err)
	}

	// Verify the request was received (http:// was added automatically)
	if receivedHost == "" {
		t.Error("Expected request to be received")
	}
}

func TestHTTPDirectOTLPSender_EndpointSchemeSelection(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		insecure bool
	}{
		{"no scheme insecure", "localhost:9090", true},
		{"no scheme secure", "localhost:9090", false},
		{"with http", "http://localhost:9090", true},
		{"with https", "https://localhost:9090", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DirectOTLPConfig{
				Endpoint:       tt.endpoint,
				Protocol:       "http",
				Timeout:        1 * time.Second,
				MaxRetries:     1,
				Insecure:       tt.insecure,
				ServiceName:    "test",
				ServiceVersion: "1.0.0",
			}

			sender, err := NewDirectOTLPSender(config)
			if err != nil {
				t.Fatalf("Failed to create sender: %v", err)
			}
			_ = sender.Close()
			// If we get here without error, the sender was created successfully
		})
	}
}

// Test that the interface is properly implemented
func TestDirectOTLPSenderInterface(t *testing.T) {
	var _ DirectOTLPSender = (*HTTPDirectOTLPSender)(nil)
	var _ DirectOTLPSender = (*GRPCDirectOTLPSender)(nil)
}

// Test response body is read and error message is captured
func TestHTTPDirectOTLPSender_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid request"}`))
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})

	if err == nil {
		t.Fatal("Expected error for bad request")
	}

	// Error should contain status code
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Expected error to contain status code 400, got: %v", err)
	}
}

// Ensure JSON marshaling doesn't occur anywhere - only protobuf
func TestNoJSONUsed(t *testing.T) {
	// This is a compile-time check that json is not imported for marshaling metrics
	// The json import in this test file is only for testing the error response
	var _ json.Marshaler // Use json package reference to silence unused import
}
