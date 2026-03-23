package metrics

import (
	"context"
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// NodeDatabaseProvider provides access to node data for metrics.
// Kept for backward compatibility with OTEL code that has not yet been migrated.
// New code should use StreamingProvider instead.
type NodeDatabaseProvider interface {
	GetScannedNodes() ([]nodes.NodeWithStatus, error)
	GetNodeVulnerabilitiesForMetrics() ([]database.NodeVulnerabilityForMetrics, error)
}

// StreamingNodeDatabaseProvider extends NodeDatabaseProvider with streaming capability.
// Kept for backward compatibility with OTEL code that has not yet been migrated.
type StreamingNodeDatabaseProvider interface {
	NodeDatabaseProvider
	StreamNodeVulnerabilitiesForMetrics(callback func(v database.NodeVulnerabilityForMetrics) error) error
}

// NodeCollectorConfig holds configuration for which node metrics to collect.
// Kept for backward compatibility with OTEL code that has not yet been migrated.
// New code should use UnifiedConfig instead.
type NodeCollectorConfig struct {
	NodeScannedEnabled                bool
	NodeVulnerabilitiesEnabled        bool
	NodeVulnerabilityRiskEnabled      bool
	NodeVulnerabilityExploitedEnabled bool
}

// OTELGauges holds the OTEL gauges for node vulnerability metrics
type OTELGauges struct {
	Vuln      metric.Float64Gauge
	Risk      metric.Float64Gauge
	Exploited metric.Float64Gauge
	Ctx       context.Context
}

// StreamVulnerabilityMetricsToOTEL streams node vulnerability metrics directly to OTEL gauges.
// This processes one row at a time to avoid OOM with large datasets.
// Used by the OTEL exporter until otel.go is migrated to use StreamingProvider.
func StreamVulnerabilityMetricsToOTEL(
	deploymentUUID, deploymentName string,
	config NodeCollectorConfig,
	streamingDB StreamingNodeDatabaseProvider,
	gauges OTELGauges,
) error {
	return streamingDB.StreamNodeVulnerabilitiesForMetrics(func(v database.NodeVulnerabilityForMetrics) error {
		labels := buildNodeVulnerabilityLabels(deploymentUUID, deploymentName, v)
		attrs := make([]attribute.KeyValue, 0, len(labels))
		for k, val := range labels {
			attrs = append(attrs, attribute.String(k, val))
		}
		opt := metric.WithAttributes(attrs...)

		if config.NodeVulnerabilitiesEnabled && gauges.Vuln != nil {
			gauges.Vuln.Record(gauges.Ctx, float64(v.Count), opt)
		}
		if config.NodeVulnerabilityRiskEnabled && gauges.Risk != nil {
			gauges.Risk.Record(gauges.Ctx, v.Score*float64(v.Count), opt)
		}
		if config.NodeVulnerabilityExploitedEnabled && gauges.Exploited != nil && v.KnownExploited > 0 {
			gauges.Exploited.Record(gauges.Ctx, float64(v.KnownExploited*v.Count), opt)
		}
		return nil
	})
}

// GetStreamingDB returns the database as a StreamingNodeDatabaseProvider if supported.
// Used by the OTEL exporter until otel.go is migrated to use StreamingProvider.
func GetStreamingDB(db NodeDatabaseProvider) StreamingNodeDatabaseProvider {
	if streamingDB, ok := db.(StreamingNodeDatabaseProvider); ok {
		return streamingDB
	}
	return nil
}

// collectNodeScannedLabels builds node labels for a NodeWithStatus.
// Exported for use in OTEL exporter.
func collectNodeScannedLabels(deploymentUUID, deploymentName string, node nodes.NodeWithStatus) map[string]string {
	return buildNodeBaseLabels(deploymentUUID, deploymentName, node)
}

// collectNodeVulnLabels builds node vulnerability labels.
// Exported for use in OTEL exporter.
func collectNodeVulnLabels(deploymentUUID, deploymentName string, v database.NodeVulnerabilityForMetrics) map[string]string {
	return buildNodeVulnerabilityLabels(deploymentUUID, deploymentName, v)
}

// collectNodeScannedMetrics builds MetricFamily for scanned nodes.
// Used by OTEL recordMetrics for now; will be removed when OTEL migrates to StreamingProvider.
func collectNodeScannedMetrics(deploymentUUID, deploymentName string, db NodeDatabaseProvider) (MetricFamily, error) {
	nodeList, err := db.GetScannedNodes()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get scanned nodes: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(nodeList))
	for _, node := range nodeList {
		metrics = append(metrics, MetricPoint{
			Labels: buildNodeBaseLabels(deploymentUUID, deploymentName, node),
			Value:  1,
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_node_scanned",
		Help:    "Bjorn2scan scanned node information",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}
