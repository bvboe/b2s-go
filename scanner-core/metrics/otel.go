package metrics

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OTELProtocol represents the protocol to use for OTLP
type OTELProtocol string

const (
	// OTELProtocolGRPC uses gRPC for OTLP communication
	OTELProtocolGRPC OTELProtocol = "grpc"
	// OTELProtocolHTTP uses HTTP for OTLP communication
	OTELProtocolHTTP OTELProtocol = "http"
)

// OTELConfig holds OpenTelemetry configuration
type OTELConfig struct {
	Endpoint        string
	Protocol        OTELProtocol
	PushInterval    time.Duration
	Insecure        bool
	UseDirectExport bool // Enable direct OTLP for high-cardinality metrics (bypasses SDK buffering)
	DirectBatchSize int  // Batch size for direct export (default 5000)
}

// OTELExporter exports metrics to an OpenTelemetry collector
type OTELExporter struct {
	collector      *Collector
	nodeCollector  *NodeCollector
	config         OTELConfig
	meterProvider  *sdkmetric.MeterProvider
	meter          metric.Meter
	gauges         map[string]metric.Float64Gauge
	ctx            context.Context
	cancel         context.CancelFunc
	directExporter *DirectOTLPExporter // For high-cardinality node metrics
	infoProvider   InfoProvider        // For direct export resource attributes
	deploymentUUID string              // For direct export resource attributes
}

// createExporter creates the appropriate OTLP exporter based on protocol
func createExporter(ctx context.Context, config OTELConfig) (sdkmetric.Exporter, error) {
	protocol := strings.ToLower(string(config.Protocol))

	switch protocol {
	case "grpc":
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(config.Endpoint),
		}
		if config.Insecure {
			opts = append(opts, otlpmetricgrpc.WithTLSCredentials(insecure.NewCredentials()))
			opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		}
		return otlpmetricgrpc.New(ctx, opts...)

	case "http":
		opts := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(config.Endpoint),
			otlpmetrichttp.WithURLPath("/api/v1/otlp/v1/metrics"),
		}
		if config.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		return otlpmetrichttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unsupported OTLP protocol: %s (supported: grpc, http)", config.Protocol)
	}
}

// NewOTELExporter creates a new OTEL metrics exporter
func NewOTELExporter(ctx context.Context, infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, collectorConfig CollectorConfig, config OTELConfig) (*OTELExporter, error) {
	// Create collector to generate metrics
	collector := NewCollector(infoProvider, deploymentUUID, database, collectorConfig)

	// Create OTLP exporter based on configured protocol
	exporter, err := createExporter(ctx, config)
	if err != nil {
		return nil, err
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("bjorn2scan"),
			semconv.ServiceVersionKey.String(infoProvider.GetVersion()),
			attribute.String("deployment.type", infoProvider.GetDeploymentType()),
			attribute.String("deployment.name", infoProvider.GetDeploymentName()),
			attribute.String("deployment.uuid", deploymentUUID),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create meter provider with periodic reader
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(config.PushInterval))),
	)

	// Set global meter provider
	otel.SetMeterProvider(meterProvider)

	// Create meter
	meter := meterProvider.Meter("bjorn2scan")

	exporterCtx, cancel := context.WithCancel(ctx)

	otelExporter := &OTELExporter{
		collector:      collector,
		config:         config,
		meterProvider:  meterProvider,
		meter:          meter,
		gauges:         make(map[string]metric.Float64Gauge),
		ctx:            exporterCtx,
		cancel:         cancel,
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
	}

	// Initialize direct exporter for high-cardinality metrics if enabled
	if config.UseDirectExport {
		batchSize := config.DirectBatchSize
		if batchSize <= 0 {
			batchSize = 5000
		}

		directConfig := DirectOTLPConfig{
			Endpoint:       config.Endpoint,
			Protocol:       string(config.Protocol),
			BatchSize:      batchSize,
			Timeout:        30 * time.Second,
			MaxRetries:     3,
			Insecure:       config.Insecure,
			ServiceName:    "bjorn2scan",
			ServiceVersion: infoProvider.GetVersion(),
			DeploymentName: infoProvider.GetDeploymentName(),
			DeploymentUUID: deploymentUUID,
		}

		directExporter, err := NewDirectOTLPExporter(directConfig)
		if err != nil {
			logging.For(logging.ComponentMetrics).Warn("failed to create direct OTLP exporter, falling back to SDK",
				"error", err)
		} else {
			otelExporter.directExporter = directExporter
			logging.For(logging.ComponentMetrics).Info("direct OTLP exporter initialized",
				"batch_size", batchSize)
		}
	}

	return otelExporter, nil
}

// SetTracker sets the metric tracker on the internal collector for staleness detection
func (e *OTELExporter) SetTracker(tracker *MetricTracker) {
	e.collector.SetTracker(tracker)
}

// SetNodeCollector sets the node collector for pushing node metrics via OTEL
func (e *OTELExporter) SetNodeCollector(nodeCollector *NodeCollector) {
	e.nodeCollector = nodeCollector
}

// Start begins pushing metrics to the OTEL collector
func (e *OTELExporter) Start() {
	go e.pushMetrics()
}

// pushMetrics periodically collects and pushes metrics
func (e *OTELExporter) pushMetrics() {
	// Push immediately on start
	e.recordMetrics()

	ticker := time.NewTicker(e.config.PushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.recordMetrics()
		case <-e.ctx.Done():
			return
		}
	}
}

// recordMetrics records all metrics by collecting structured data and converting to OTLP
func (e *OTELExporter) recordMetrics() {
	// Collect image metrics using the same method as /metrics endpoint
	data, err := e.collector.Collect()
	if err != nil {
		logging.For(logging.ComponentMetrics).Error("error collecting metrics for OTEL", "error", err)
		return
	}

	// Record each image metric family
	e.recordMetricFamilies(data.Families)

	// Collect and record node metrics if node collector is configured
	if e.nodeCollector != nil {
		// First, collect node_scanned metrics (small dataset) via SDK
		nodeScannedData, err := e.nodeCollector.CollectNodeScannedOnly()
		if err != nil {
			logging.For(logging.ComponentMetrics).Error("error collecting node scanned metrics for OTEL", "error", err)
		} else {
			e.recordMetricFamilies(nodeScannedData.Families)
		}

		// Node vulnerability metrics via direct export (high cardinality) or SDK fallback
		if e.directExporter != nil {
			// Use direct OTLP export to avoid SDK buffering OOM
			streamingDB := e.nodeCollector.GetStreamingDatabase()
			if streamingDB != nil {
				if err := e.directExporter.StreamNodeVulnerabilityMetrics(
					e.ctx,
					streamingDB,
					e.nodeCollector.GetConfig(),
					e.deploymentUUID,
					e.infoProvider.GetDeploymentName(),
				); err != nil {
					logging.For(logging.ComponentMetrics).Error("error streaming node vulnerability metrics via direct OTLP", "error", err)
				}
			} else {
				logging.For(logging.ComponentMetrics).Warn("database does not support streaming, falling back to SDK export")
				if err := e.streamNodeVulnerabilityMetrics(); err != nil {
					logging.For(logging.ComponentMetrics).Error("error streaming node vulnerability metrics for OTEL", "error", err)
				}
			}
		} else {
			// Fallback to SDK-based export (will OOM with large datasets)
			if err := e.streamNodeVulnerabilityMetrics(); err != nil {
				logging.For(logging.ComponentMetrics).Error("error streaming node vulnerability metrics for OTEL", "error", err)
			}
		}
	}
}

// streamNodeVulnerabilityMetrics streams node vulnerability metrics to OTEL gauges
func (e *OTELExporter) streamNodeVulnerabilityMetrics() error {
	// Get or create gauges for each metric type
	vulnGauge, err := e.getOrCreateGauge("bjorn2scan_node_vulnerability", "Bjorn2scan vulnerability information for nodes")
	if err != nil {
		return fmt.Errorf("failed to create vuln gauge: %w", err)
	}
	riskGauge, err := e.getOrCreateGauge("bjorn2scan_node_vulnerability_risk", "Bjorn2scan vulnerability risk scores for nodes")
	if err != nil {
		return fmt.Errorf("failed to create risk gauge: %w", err)
	}
	exploitedGauge, err := e.getOrCreateGauge("bjorn2scan_node_vulnerability_exploited", "Bjorn2scan known exploited vulnerabilities (CISA KEV) on nodes")
	if err != nil {
		return fmt.Errorf("failed to create exploited gauge: %w", err)
	}

	return e.nodeCollector.StreamVulnerabilityMetricsToOTEL(OTELGauges{
		Vuln:      vulnGauge,
		Risk:      riskGauge,
		Exploited: exploitedGauge,
		Ctx:       e.ctx,
	})
}

// recordMetricFamilies records a slice of metric families to OTEL
func (e *OTELExporter) recordMetricFamilies(families []MetricFamily) {
	for _, family := range families {
		// Get or create gauge for this metric
		gauge, err := e.getOrCreateGauge(family.Name, family.Help)
		if err != nil {
			logging.For(logging.ComponentMetrics).Error("error creating gauge",
				"metric_name", family.Name,
				"error", err)
			continue
		}

		// Record all metrics in this family
		for _, m := range family.Metrics {
			// Convert labels map to OpenTelemetry attributes
			attrs := make([]attribute.KeyValue, 0, len(m.Labels))
			for k, v := range m.Labels {
				attrs = append(attrs, attribute.String(k, v))
			}

			// Record the metric
			gauge.Record(e.ctx, m.Value, metric.WithAttributes(attrs...))
		}
	}
}

// getOrCreateGauge returns an existing gauge or creates a new one
func (e *OTELExporter) getOrCreateGauge(name, help string) (metric.Float64Gauge, error) {
	// Check if gauge already exists
	if gauge, ok := e.gauges[name]; ok {
		return gauge, nil
	}

	// Create new gauge
	gauge, err := e.meter.Float64Gauge(name, metric.WithDescription(help))
	if err != nil {
		return nil, err
	}

	// Store for reuse
	e.gauges[name] = gauge
	return gauge, nil
}

// Shutdown gracefully shuts down the OTEL exporter
func (e *OTELExporter) Shutdown() error {
	e.cancel()

	// Close direct exporter if it was initialized
	if e.directExporter != nil {
		if err := e.directExporter.Close(); err != nil {
			logging.For(logging.ComponentMetrics).Error("error closing direct OTLP exporter", "error", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.meterProvider.Shutdown(ctx); err != nil {
		logging.For(logging.ComponentMetrics).Error("error shutting down OTEL meter provider", "error", err)
		return err
	}

	return nil
}
