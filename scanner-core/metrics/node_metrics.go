package metrics

import (
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// NodeDatabaseProvider provides access to node data for metrics
type NodeDatabaseProvider interface {
	GetScannedNodes() ([]nodes.NodeWithStatus, error)
	GetNodeVulnerabilitiesForMetrics() ([]database.NodeVulnerabilityForMetrics, error)
}

// NodeCollectorConfig holds configuration for which node metrics to collect
type NodeCollectorConfig struct {
	NodeScannedEnabled              bool // Enable bjorn2scan_node_scanned metric
	NodeVulnerabilitiesEnabled      bool // Enable bjorn2scan_node_vulnerability metric
	NodeVulnerabilityRiskEnabled    bool // Enable bjorn2scan_node_vulnerability_risk metric
	NodeVulnerabilityExploitedEnabled bool // Enable bjorn2scan_node_vulnerability_exploited metric
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

	// Collect node scanned metrics if enabled
	if c.config.NodeScannedEnabled {
		family, err := c.collectNodeScannedMetrics()
		if err != nil {
			return nil, err
		}
		data.Families = append(data.Families, family)
	}

	// Fetch vulnerability data once for all vulnerability metrics (performance optimization)
	var vulnData []database.NodeVulnerabilityForMetrics
	needsVulnData := c.config.NodeVulnerabilitiesEnabled ||
		c.config.NodeVulnerabilityRiskEnabled ||
		c.config.NodeVulnerabilityExploitedEnabled

	if needsVulnData {
		var err error
		vulnData, err = c.database.GetNodeVulnerabilitiesForMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to get node vulnerabilities for metrics: %w", err)
		}
	}

	// Collect all vulnerability metrics in a single pass (memory optimization)
	// This avoids iterating over the same data 3 times and reuses label maps
	vulnFamily, riskFamily, exploitedFamily := c.collectAllVulnerabilityMetrics(
		vulnData,
		c.config.NodeVulnerabilitiesEnabled,
		c.config.NodeVulnerabilityRiskEnabled,
		c.config.NodeVulnerabilityExploitedEnabled,
	)

	if c.config.NodeVulnerabilitiesEnabled {
		data.Families = append(data.Families, vulnFamily)
	}
	if c.config.NodeVulnerabilityRiskEnabled {
		data.Families = append(data.Families, riskFamily)
	}
	if c.config.NodeVulnerabilityExploitedEnabled {
		data.Families = append(data.Families, exploitedFamily)
	}

	return data, nil
}

// buildNodeBaseLabels creates the common label map used by node metrics
func (c *NodeCollector) buildNodeBaseLabels(node nodes.NodeWithStatus) map[string]string {
	return map[string]string{
		"deployment_uuid": c.deploymentUUID,
		"deployment_name": c.deploymentName,
		"node":            node.Name,
		"hostname":        node.Hostname,
		"os_release":      node.OSRelease,
		"kernel_version":  node.KernelVersion,
		"architecture":    node.Architecture,
		"instance_type":   "NODE",
	}
}

// buildNodeVulnerabilityLabels creates labels for node vulnerability metrics
func (c *NodeCollector) buildNodeVulnerabilityLabels(v database.NodeVulnerabilityForMetrics) map[string]string {
	vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, v.VulnID)

	return map[string]string{
		"deployment_uuid":  c.deploymentUUID,
		"deployment_name":  c.deploymentName,
		"node":             v.NodeName,
		"hostname":         v.Hostname,
		"os_release":       v.OSRelease,
		"kernel_version":   v.KernelVersion,
		"architecture":     v.Architecture,
		"instance_type":    "NODE",
		"severity":         v.Severity,
		"vulnerability":    v.CVEID,
		"vulnerability_id": vulnerabilityID,
		"package_name":     v.PackageName,
		"package_version":  v.PackageVersion,
		"package_type":     v.PackageType,
		"fix_status":       v.FixStatus,
		"fixed_version":    v.FixVersion,
	}
}

// collectNodeScannedMetrics generates bjorn2scan_node_scanned metrics for all scanned nodes
func (c *NodeCollector) collectNodeScannedMetrics() (MetricFamily, error) {
	nodeList, err := c.database.GetScannedNodes()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get scanned nodes: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(nodeList))

	for _, node := range nodeList {
		metrics = append(metrics, MetricPoint{
			Labels: c.buildNodeBaseLabels(node),
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

// collectAllVulnerabilityMetrics generates all node vulnerability metrics in a single pass.
// This is a memory optimization that avoids iterating over the same data 3 times
// and reuses the same label map for all three metric types.
func (c *NodeCollector) collectAllVulnerabilityMetrics(
	vulns []database.NodeVulnerabilityForMetrics,
	collectVuln, collectRisk, collectExploited bool,
) (vulnFamily, riskFamily, exploitedFamily MetricFamily) {
	// Pre-allocate slices based on what we need to collect
	var vulnMetrics, riskMetrics, exploitedMetrics []MetricPoint
	if collectVuln {
		vulnMetrics = make([]MetricPoint, 0, len(vulns))
	}
	if collectRisk {
		riskMetrics = make([]MetricPoint, 0, len(vulns))
	}
	if collectExploited {
		// Exploited metrics are typically fewer, but we don't know how many upfront
		exploitedMetrics = make([]MetricPoint, 0, len(vulns)/10)
	}

	// Single pass over all vulnerabilities
	for _, v := range vulns {
		// Build labels once per vulnerability (reused across all metric types)
		labels := c.buildNodeVulnerabilityLabels(v)

		if collectVuln {
			vulnMetrics = append(vulnMetrics, MetricPoint{
				Labels: labels,
				Value:  float64(v.Count),
			})
		}

		if collectRisk {
			riskMetrics = append(riskMetrics, MetricPoint{
				Labels: labels,
				Value:  v.Score * float64(v.Count),
			})
		}

		if collectExploited && v.KnownExploited > 0 {
			exploitedMetrics = append(exploitedMetrics, MetricPoint{
				Labels: labels,
				Value:  float64(v.KnownExploited * v.Count),
			})
		}
	}

	vulnFamily = MetricFamily{
		Name:    "bjorn2scan_node_vulnerability",
		Help:    "Bjorn2scan vulnerability information for nodes",
		Type:    "gauge",
		Metrics: vulnMetrics,
	}

	riskFamily = MetricFamily{
		Name:    "bjorn2scan_node_vulnerability_risk",
		Help:    "Bjorn2scan vulnerability risk scores for nodes",
		Type:    "gauge",
		Metrics: riskMetrics,
	}

	exploitedFamily = MetricFamily{
		Name:    "bjorn2scan_node_vulnerability_exploited",
		Help:    "Bjorn2scan known exploited vulnerabilities (CISA KEV) on nodes",
		Type:    "gauge",
		Metrics: exploitedMetrics,
	}

	return vulnFamily, riskFamily, exploitedFamily
}
