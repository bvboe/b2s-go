package metrics

import (
	"context"
	"fmt"
	"strings"
	"time"

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

	"github.com/bvboe/b2s-go/scanner-core/database"
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
	UseDirectExport bool // Enable direct OTLP for high-cardinality node vulnerability metrics
	DirectBatchSize int  // Batch size for direct export (default 5000)
}

// OTELExporter exports metrics to an OpenTelemetry collector
type OTELExporter struct {
	provider       StreamingProvider
	unifiedConfig  UnifiedConfig
	config         OTELConfig
	meterProvider  *sdkmetric.MeterProvider
	meter          metric.Meter
	gauges         map[string]metric.Float64Gauge
	ctx            context.Context
	cancel         context.CancelFunc
	directExporter *DirectOTLPExporter // For high-cardinality node vulnerability metrics
	infoProvider   InfoProvider
	deploymentUUID string
	staleness      *StalenessStore
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

// NewOTELExporter creates a new OTEL metrics exporter.
// provider must implement StreamingProvider (e.g. *database.DB).
// staleness is shared with the Prometheus handler for consistent NaN behaviour.
func NewOTELExporter(
	ctx context.Context,
	infoProvider InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	unifiedConfig UnifiedConfig,
	config OTELConfig,
	staleness *StalenessStore,
) (*OTELExporter, error) {
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
		provider:       provider,
		unifiedConfig:  unifiedConfig,
		config:         config,
		meterProvider:  meterProvider,
		meter:          meter,
		gauges:         make(map[string]metric.Float64Gauge),
		ctx:            exporterCtx,
		cancel:         cancel,
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
		staleness:      staleness,
	}

	// Initialize direct exporter for high-cardinality node vulnerability metrics if enabled.
	// This bypasses SDK buffering which can OOM for large vulnerability datasets.
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

		directExp, err := NewDirectOTLPExporter(directConfig)
		if err != nil {
			log.Warn("failed to create direct OTLP exporter, falling back to SDK",
				"error", err)
		} else {
			otelExporter.directExporter = directExp
			log.Info("direct OTLP exporter initialized", "batch_size", batchSize)
		}
	}

	return otelExporter, nil
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

// recordMetrics records all metrics to OTEL gauges via streaming.
// Container vulnerability metrics use the SDK path (each gauge.Record call is lightweight).
// Node vulnerability metrics optionally use the direct OTLP path (bypasses SDK buffering).
func (e *OTELExporter) recordMetrics() {
	cycleStart := time.Now()
	deploymentName := e.infoProvider.GetDeploymentName()
	cycleStartUnix := cycleStart.Unix()

	staleRows, err := e.staleness.QueryStale(cycleStart)
	if err != nil {
		log.Error("failed to query stale metrics for OTEL", "error", err)
		// Continue without NaN emission rather than aborting entirely.
	}

	emit := func(familyName, help string, labels map[string]string, value float64) {
		gauge, err := e.getOrCreateGauge(familyName, help)
		if err != nil {
			log.Error("error creating OTEL gauge", "metric_name", familyName, "error", err)
			return
		}
		attrs := make([]attribute.KeyValue, 0, len(labels))
		for k, v := range labels {
			attrs = append(attrs, attribute.String(k, v))
		}
		gauge.Record(e.ctx, value, metric.WithAttributes(attrs...))
	}

	onBatchFull := func(batch []database.StalenessRow) {
		if err := e.staleness.FlushBatch(batch, cycleStartUnix); err != nil {
			log.Warn("failed to flush staleness batch in OTEL exporter", "error", err)
		}
	}

	// When using the direct OTLP path for node vulnerabilities, exclude them from
	// collectMetrics (they are handled separately below).
	// Note: direct OTLP path does not update staleness tracking — known limitation.
	cfg := e.unifiedConfig
	if e.directExporter != nil {
		cfg.NodeVulnerabilitiesEnabled = false
		cfg.NodeVulnerabilityRiskEnabled = false
		cfg.NodeVulnerabilityExploitedEnabled = false
	}

	remaining, err := collectMetrics(e.provider, cfg, e.infoProvider, e.deploymentUUID,
		deploymentName, cycleStartUnix, staleRows, e.staleness.BatchSize(), emit, onBatchFull)
	if err != nil {
		log.Error("error collecting metrics for OTEL", "error", err)
	}
	if len(remaining) > 0 {
		onBatchFull(remaining)
	}

	// ─── Node vulnerabilities via direct OTLP (bypasses SDK buffering) ────────
	needsNodeVulns := e.unifiedConfig.NodeVulnerabilitiesEnabled ||
		e.unifiedConfig.NodeVulnerabilityRiskEnabled ||
		e.unifiedConfig.NodeVulnerabilityExploitedEnabled
	if needsNodeVulns && e.directExporter != nil {
		nodeConfig := NodeCollectorConfig{
			NodeVulnerabilitiesEnabled:        e.unifiedConfig.NodeVulnerabilitiesEnabled,
			NodeVulnerabilityRiskEnabled:      e.unifiedConfig.NodeVulnerabilityRiskEnabled,
			NodeVulnerabilityExploitedEnabled: e.unifiedConfig.NodeVulnerabilityExploitedEnabled,
		}
		if err := e.directExporter.StreamNodeVulnerabilityMetrics(
			e.ctx, e.provider, nodeConfig, e.deploymentUUID, deploymentName,
		); err != nil {
			log.Error("error streaming node vulnerability metrics via direct OTLP", "error", err)
		}
	}

	go e.staleness.DeleteExpired(cycleStart)
}

// getOrCreateGauge returns an existing gauge or creates a new one
func (e *OTELExporter) getOrCreateGauge(name, help string) (metric.Float64Gauge, error) {
	if gauge, ok := e.gauges[name]; ok {
		return gauge, nil
	}
	opts := []metric.Float64GaugeOption{}
	if help != "" {
		opts = append(opts, metric.WithDescription(help))
	}
	gauge, err := e.meter.Float64Gauge(name, opts...)
	if err != nil {
		return nil, err
	}
	e.gauges[name] = gauge
	return gauge, nil
}

// Shutdown gracefully shuts down the OTEL exporter
func (e *OTELExporter) Shutdown() error {
	e.cancel()

	if e.directExporter != nil {
		if err := e.directExporter.Close(); err != nil {
			log.Error("error closing direct OTLP exporter", "error", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.meterProvider.Shutdown(ctx); err != nil {
		log.Error("error shutting down OTEL meter provider", "error", err)
		return err
	}

	return nil
}
