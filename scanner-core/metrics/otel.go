package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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

	// Query stale entries — shared staleness state with the Prometheus handler.
	staleRows, err := e.staleness.QueryStale(cycleStart)
	if err != nil {
		log.Error("failed to query stale metrics for OTEL", "error", err)
		// Continue without NaN emission rather than aborting entirely.
	}

	// In-flight staleness batch
	batch := make([]database.StalenessRow, 0, e.staleness.BatchSize())

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.staleness.FlushBatch(batch, cycleStartUnix); err != nil {
			log.Warn("failed to flush staleness batch in OTEL exporter", "error", err)
		}
		batch = batch[:0]
	}

	// recordPoint records a single data point to an OTEL gauge and queues it for staleness tracking.
	recordPoint := func(familyName, help string, labels map[string]string, value float64) {
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

		labelsJSON, marshalErr := json.Marshal(labels)
		if marshalErr != nil {
			log.Warn("failed to marshal labels for staleness tracking", "error", marshalErr)
			return
		}
		batch = append(batch, database.StalenessRow{
			MetricKey:    generateMetricKey(familyName, labels),
			FamilyName:   familyName,
			LabelsJSON:   string(labelsJSON),
			LastSeenUnix: cycleStartUnix,
		})
		if len(batch) >= e.staleness.BatchSize() {
			flushBatch()
		}
	}

	// ─── 1. Deployment metric ─────────────────────────────────────────────────
	if e.unifiedConfig.DeploymentEnabled {
		labels := buildDeploymentLabels(e.infoProvider, e.deploymentUUID, deploymentName)
		recordPoint("bjorn2scan_deployment", familyMeta["bjorn2scan_deployment"][0], labels, 1)
	}

	// ─── 2. Image scanned ────────────────────────────────────────────────────
	if e.unifiedConfig.ScannedContainersEnabled {
		if err := e.provider.StreamScannedContainers(func(ctr database.ScannedContainer) error {
			info := containerInfo{
				NodeName:  ctr.NodeName,
				Namespace: ctr.Namespace,
				Pod:       ctr.Pod,
				Name:      ctr.Name,
				Reference: ctr.Reference,
				Digest:    ctr.Digest,
				OSName:    ctr.OSName,
				Arch:      ctr.Architecture,
			}
			labels := buildContainerBaseLabels(e.deploymentUUID, deploymentName, info)
			recordPoint("bjorn2scan_image_scanned", familyMeta["bjorn2scan_image_scanned"][0], labels, 1)
			return nil
		}); err != nil {
			log.Error("error streaming scanned containers for OTEL", "error", err)
		}
	}

	// ─── 3. Image vulnerabilities (3 families, single DB pass) ───────────────
	needsVulns := e.unifiedConfig.VulnerabilitiesEnabled ||
		e.unifiedConfig.VulnerabilityExploitedEnabled ||
		e.unifiedConfig.VulnerabilityRiskEnabled
	if needsVulns {
		if err := e.provider.StreamContainerVulnerabilities(func(v database.ContainerVulnerability) error {
			labels := buildContainerVulnerabilityLabels(e.deploymentUUID, deploymentName, v)
			if e.unifiedConfig.VulnerabilitiesEnabled {
				recordPoint("bjorn2scan_image_vulnerability", familyMeta["bjorn2scan_image_vulnerability"][0], labels, float64(v.Count))
			}
			if e.unifiedConfig.VulnerabilityRiskEnabled {
				recordPoint("bjorn2scan_image_vulnerability_risk", familyMeta["bjorn2scan_image_vulnerability_risk"][0], labels, v.Risk*float64(v.Count))
			}
			if e.unifiedConfig.VulnerabilityExploitedEnabled && v.KnownExploited > 0 {
				recordPoint("bjorn2scan_image_vulnerability_exploited", familyMeta["bjorn2scan_image_vulnerability_exploited"][0], labels, float64(v.KnownExploited*v.Count))
			}
			return nil
		}); err != nil {
			log.Error("error streaming container vulnerabilities for OTEL", "error", err)
		}
	}

	// ─── 4. Image scan status ────────────────────────────────────────────────
	if e.unifiedConfig.ImageScanStatusEnabled {
		statusCounts, err := e.provider.GetImageScanStatusCounts()
		if err != nil {
			log.Error("error getting image scan status counts for OTEL", "error", err)
		} else {
			for _, sc := range statusCounts {
				labels := map[string]string{
					"deployment_uuid": e.deploymentUUID,
					"scan_status":     sc.Status,
				}
				recordPoint("bjorn2scan_image_scan_status", familyMeta["bjorn2scan_image_scan_status"][0], labels, float64(sc.Count))
			}
		}
	}

	// ─── 5. Node scanned ─────────────────────────────────────────────────────
	if e.unifiedConfig.NodeScannedEnabled {
		nodeList, err := e.provider.GetScannedNodes()
		if err != nil {
			log.Error("error getting scanned nodes for OTEL", "error", err)
		} else {
			for _, node := range nodeList {
				labels := buildNodeBaseLabels(e.deploymentUUID, deploymentName, node)
				recordPoint("bjorn2scan_node_scanned", familyMeta["bjorn2scan_node_scanned"][0], labels, 1)
			}
		}
	}

	// ─── 6. Node vulnerabilities ──────────────────────────────────────────────
	// Use direct OTLP export if available (bypasses SDK buffering for large datasets).
	// Note: direct OTLP path does not update staleness tracking — this is a known limitation.
	needsNodeVulns := e.unifiedConfig.NodeVulnerabilitiesEnabled ||
		e.unifiedConfig.NodeVulnerabilityRiskEnabled ||
		e.unifiedConfig.NodeVulnerabilityExploitedEnabled
	if needsNodeVulns {
		if e.directExporter != nil {
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
		} else {
			// SDK fallback: call gauge.Record per row (may OOM for very large datasets)
			if err := e.provider.StreamNodeVulnerabilitiesForMetrics(func(v database.NodeVulnerabilityForMetrics) error {
				labels := buildNodeVulnerabilityLabels(e.deploymentUUID, deploymentName, v)
				if e.unifiedConfig.NodeVulnerabilitiesEnabled {
					recordPoint("bjorn2scan_node_vulnerability", familyMeta["bjorn2scan_node_vulnerability"][0], labels, float64(v.Count))
				}
				if e.unifiedConfig.NodeVulnerabilityRiskEnabled {
					recordPoint("bjorn2scan_node_vulnerability_risk", familyMeta["bjorn2scan_node_vulnerability_risk"][0], labels, v.Score*float64(v.Count))
				}
				if e.unifiedConfig.NodeVulnerabilityExploitedEnabled && v.KnownExploited > 0 {
					recordPoint("bjorn2scan_node_vulnerability_exploited", familyMeta["bjorn2scan_node_vulnerability_exploited"][0], labels, float64(v.KnownExploited*v.Count))
				}
				return nil
			}); err != nil {
				log.Error("error streaming node vulnerability metrics for OTEL", "error", err)
			}
		}
	}

	// ─── Flush remaining staleness batch ─────────────────────────────────────
	flushBatch()

	// ─── 7. Emit NaN for stale metrics ───────────────────────────────────────
	for _, row := range staleRows {
		var labels map[string]string
		if err := json.Unmarshal([]byte(row.LabelsJSON), &labels); err != nil {
			log.Warn("skipping stale OTEL metric: invalid labels JSON",
				"family", row.FamilyName, "metric_key", row.MetricKey, "error", err)
			continue
		}
		gauge, err := e.getOrCreateGauge(row.FamilyName, "")
		if err != nil {
			log.Error("error creating OTEL gauge for stale metric", "error", err)
			continue
		}
		attrs := make([]attribute.KeyValue, 0, len(labels))
		for k, v := range labels {
			attrs = append(attrs, attribute.String(k, v))
		}
		gauge.Record(e.ctx, math.NaN(), metric.WithAttributes(attrs...))
	}

	// Delete expired entries asynchronously
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
