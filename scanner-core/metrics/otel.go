package metrics

import (
	"context"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OTELConfig holds OpenTelemetry configuration
type OTELConfig struct {
	Endpoint     string
	PushInterval time.Duration
	Insecure     bool
}

// OTELExporter exports metrics to an OpenTelemetry collector
type OTELExporter struct {
	collector      *Collector
	config         OTELConfig
	meterProvider  *sdkmetric.MeterProvider
	deploymentGauge metric.Int64Gauge
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewOTELExporter creates a new OTEL metrics exporter
func NewOTELExporter(ctx context.Context, infoProvider InfoProvider, deploymentUUID string, config OTELConfig) (*OTELExporter, error) {
	// Create collector to generate metrics
	collector := NewCollector(infoProvider, deploymentUUID)

	// Create OTLP exporter
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(config.Endpoint),
	}
	if config.Insecure {
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(insecure.NewCredentials()))
		opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
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
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	exporterCtx, cancel := context.WithCancel(ctx)

	return &OTELExporter{
		collector:       collector,
		config:          config,
		meterProvider:   meterProvider,
		deploymentGauge: deploymentGauge,
		ctx:             exporterCtx,
		cancel:          cancel,
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

// recordMetrics records the current deployment metric
func (e *OTELExporter) recordMetrics() {
	// Use collector to generate labels (even though we're not using the text output)
	// This ensures consistency between HTTP and OTEL metrics
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
