package metrics

import (
	"context"
	"fmt"
	"log"
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
	Endpoint     string
	Protocol     OTELProtocol
	PushInterval time.Duration
	Insecure     bool
}

// OTELExporter exports metrics to an OpenTelemetry collector
type OTELExporter struct {
	collector             *Collector
	config                OTELConfig
	meterProvider         *sdkmetric.MeterProvider
	deploymentGauge       metric.Int64Gauge
	scannedInstanceGauge  metric.Int64Gauge
	ctx                   context.Context
	cancel                context.CancelFunc
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

	// Create deployment gauge
	deploymentGauge, err := meter.Int64Gauge("bjorn2scan_deployment",
		metric.WithDescription("Bjorn2scan deployment information"),
	)
	if err != nil {
		return nil, err
	}

	// Create scanned instance gauge
	scannedInstanceGauge, err := meter.Int64Gauge("bjorn2scan_scanned_instance",
		metric.WithDescription("Bjorn2scan scanned container instance information"),
	)
	if err != nil {
		return nil, err
	}

	exporterCtx, cancel := context.WithCancel(ctx)

	return &OTELExporter{
		collector:            collector,
		config:               config,
		meterProvider:        meterProvider,
		deploymentGauge:      deploymentGauge,
		scannedInstanceGauge: scannedInstanceGauge,
		ctx:                  exporterCtx,
		cancel:               cancel,
	}, nil
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

// recordMetrics records the current metrics based on collector config
func (e *OTELExporter) recordMetrics() {
	// Record deployment metric if enabled
	if e.collector.config.DeploymentEnabled {
		e.recordDeploymentMetric()
	}

	// Record scanned instance metrics if enabled
	if e.collector.config.ScannedInstancesEnabled && e.collector.database != nil {
		e.recordScannedInstanceMetrics()
	}
}

// recordDeploymentMetric records the deployment gauge metric
func (e *OTELExporter) recordDeploymentMetric() {
	deploymentName := e.collector.infoProvider.GetDeploymentName()
	deploymentType := e.collector.infoProvider.GetDeploymentType()
	version := e.collector.infoProvider.GetVersion()

	// Record deployment gauge with all labels as attributes
	e.deploymentGauge.Record(e.ctx, 1,
		metric.WithAttributes(
			attribute.String("deployment_uuid", e.collector.deploymentUUID),
			attribute.String("deployment_name", deploymentName),
			attribute.String("deployment_type", deploymentType),
			attribute.String("bjorn2scan_version", version),
		),
	)
}

// recordScannedInstanceMetrics records scanned container instance metrics
func (e *OTELExporter) recordScannedInstanceMetrics() {
	instances, err := e.collector.database.GetScannedContainerInstances()
	if err != nil {
		log.Printf("Error getting scanned container instances for OTEL metrics: %v", err)
		return
	}

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", e.collector.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", e.collector.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			e.collector.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageID := fmt.Sprintf("%s.%s.%s",
			e.collector.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			e.collector.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			e.collector.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)

		// Record scanned instance gauge with all labels as attributes
		e.scannedInstanceGauge.Record(e.ctx, 1,
			metric.WithAttributes(
				attribute.String("deployment_uuid", e.collector.deploymentUUID),
				attribute.String("deployment_uuid_host_name", deploymentUUIDHostName),
				attribute.String("deployment_uuid_namespace", deploymentUUIDNamespace),
				attribute.String("deployment_uuid_namespace_image", deploymentUUIDNamespaceImage),
				attribute.String("deployment_uuid_namespace_image_id", deploymentUUIDNamespaceImageID),
				attribute.String("deployment_uuid_namespace_pod", deploymentUUIDNamespacePod),
				attribute.String("deployment_uuid_namespace_pod_container", deploymentUUIDNamespacePodContainer),
				attribute.String("host_name", instance.NodeName),
				attribute.String("namespace", instance.Namespace),
				attribute.String("pod", instance.Pod),
				attribute.String("container", instance.Container),
				attribute.String("distro", instance.OSName),
				attribute.String("image_repo", instance.Repository),
				attribute.String("image_tag", instance.Tag),
				attribute.String("image_digest", instance.Digest),
				attribute.String("instance_type", "CONTAINER"),
			),
		)
	}
}

// Shutdown gracefully shuts down the OTEL exporter
func (e *OTELExporter) Shutdown() error {
	e.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.meterProvider.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down OTEL meter provider: %v", err)
		return err
	}

	return nil
}
