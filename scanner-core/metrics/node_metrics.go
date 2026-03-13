package metrics

import (
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// NodeDatabaseProvider provides access to node data for metrics
type NodeDatabaseProvider interface {
	GetAllNodes() ([]nodes.NodeWithStatus, error)
	GetNodeSummaries() ([]nodes.NodeSummary, error)
}

// NodeCollectorConfig holds configuration for which node metrics to collect
type NodeCollectorConfig struct {
	NodeScanStatusEnabled      bool // Enable bjorn2scan_node_scan_status metric
	NodeVulnerabilitiesEnabled bool // Enable bjorn2scan_node_vulnerabilities metric
	NodePackagesEnabled        bool // Enable bjorn2scan_node_packages metric
}

// NodeCollector collects node-related metrics
type NodeCollector struct {
	deploymentUUID string
	deploymentName string
	database       NodeDatabaseProvider
	config         NodeCollectorConfig
}

// NewNodeCollector creates a new node metrics collector
func NewNodeCollector(deploymentUUID, deploymentName string, database NodeDatabaseProvider, config NodeCollectorConfig) *NodeCollector {
	return &NodeCollector{
		deploymentUUID: deploymentUUID,
		deploymentName: deploymentName,
		database:       database,
		config:         config,
	}
}

// Collect generates node-related metrics data
func (c *NodeCollector) Collect() (*MetricsData, error) {
	data := &MetricsData{
		Families: make([]MetricFamily, 0),
	}

	if c.database == nil {
		return data, nil
	}

	// Collect node scan status metrics if enabled
	if c.config.NodeScanStatusEnabled {
		family, err := c.collectNodeScanStatusMetrics()
		if err != nil {
			return nil, err
		}
		data.Families = append(data.Families, family)
	}

	// Collect node vulnerabilities metrics if enabled
	if c.config.NodeVulnerabilitiesEnabled {
		family, err := c.collectNodeVulnerabilitiesMetrics()
		if err != nil {
			return nil, err
		}
		data.Families = append(data.Families, family)
	}

	// Collect node packages metrics if enabled
	if c.config.NodePackagesEnabled {
		family, err := c.collectNodePackagesMetrics()
		if err != nil {
			return nil, err
		}
		data.Families = append(data.Families, family)
	}

	return data, nil
}

// collectNodeScanStatusMetrics generates bjorn2scan_node_scan_status metrics
func (c *NodeCollector) collectNodeScanStatusMetrics() (MetricFamily, error) {
	nodeList, err := c.database.GetAllNodes()
	if err != nil {
		return MetricFamily{}, err
	}

	metrics := make([]MetricPoint, 0, len(nodeList))

	for _, node := range nodeList {
		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid": c.deploymentUUID,
				"deployment_name": c.deploymentName,
				"node":            node.Name,
				"hostname":        node.Hostname,
				"os_release":      node.OSRelease,
				"architecture":    node.Architecture,
				"status":          node.Status,
			},
			Value: 1,
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_node_scan_status",
		Help:    "Bjorn2scan node scan status information",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}

// collectNodeVulnerabilitiesMetrics generates bjorn2scan_node_vulnerabilities metrics
func (c *NodeCollector) collectNodeVulnerabilitiesMetrics() (MetricFamily, error) {
	summaries, err := c.database.GetNodeSummaries()
	if err != nil {
		return MetricFamily{}, err
	}

	// Create one metric per node per severity
	metrics := make([]MetricPoint, 0, len(summaries)*6) // 6 severity levels

	for _, summary := range summaries {
		baseLabels := map[string]string{
			"deployment_uuid": c.deploymentUUID,
			"deployment_name": c.deploymentName,
			"node":            summary.NodeName,
		}

		// Critical
		if summary.Critical > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "Critical"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.Critical),
			})
		}

		// High
		if summary.High > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "High"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.High),
			})
		}

		// Medium
		if summary.Medium > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "Medium"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.Medium),
			})
		}

		// Low
		if summary.Low > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "Low"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.Low),
			})
		}

		// Negligible
		if summary.Negligible > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "Negligible"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.Negligible),
			})
		}

		// Unknown
		if summary.Unknown > 0 {
			labels := copyMap(baseLabels)
			labels["severity"] = "Unknown"
			metrics = append(metrics, MetricPoint{
				Labels: labels,
				Value:  float64(summary.Unknown),
			})
		}
	}

	return MetricFamily{
		Name:    "bjorn2scan_node_vulnerabilities",
		Help:    "Bjorn2scan node vulnerability counts by severity",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}

// collectNodePackagesMetrics generates bjorn2scan_node_packages_total metrics
func (c *NodeCollector) collectNodePackagesMetrics() (MetricFamily, error) {
	summaries, err := c.database.GetNodeSummaries()
	if err != nil {
		return MetricFamily{}, err
	}

	metrics := make([]MetricPoint, 0, len(summaries))

	for _, summary := range summaries {
		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid": c.deploymentUUID,
				"deployment_name": c.deploymentName,
				"node":            summary.NodeName,
			},
			Value: float64(summary.PackageCount),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_node_packages_total",
		Help:    "Bjorn2scan total packages installed on node",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}

// copyMap creates a shallow copy of a string map
func copyMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
