// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

import (
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// InfoProvider provides deployment information for metrics labels
type InfoProvider interface {
	GetDeploymentName() string // hostname for agent, cluster name for k8s
	GetDeploymentType() string // "agent" or "kubernetes"
	GetVersion() string
	GetDeploymentIP() string   // primary outbound IP for agent, node IP for k8s
	GetConsoleURL() string     // web UI URL (empty if disabled)
	GetGrypeDBBuilt() string   // grype vulnerability database build timestamp (RFC3339 format, empty if unavailable)
}

// DatabaseProvider provides access to container data
type DatabaseProvider interface {
	GetScannedContainers() ([]database.ScannedContainer, error)
	GetContainerVulnerabilities() ([]database.ContainerVulnerability, error)
	GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error)
}

// CollectorConfig holds configuration for which metrics to collect
type CollectorConfig struct {
	DeploymentEnabled             bool
	ScannedContainersEnabled      bool
	VulnerabilitiesEnabled        bool
	VulnerabilityExploitedEnabled bool
	VulnerabilityRiskEnabled      bool
	ImageScanStatusEnabled        bool
}

// Collector collects metrics and formats them for Prometheus
type Collector struct {
	infoProvider   InfoProvider
	deploymentUUID string
	deploymentName string // Cached deployment name for per-instance metrics
	database       DatabaseProvider
	config         CollectorConfig
	tracker        *MetricTracker // Optional tracker for staleness detection
}

// NewCollector creates a new metrics collector
func NewCollector(infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig) *Collector {
	deploymentName := ""
	if infoProvider != nil {
		deploymentName = infoProvider.GetDeploymentName()
	}
	return &Collector{
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
		deploymentName: deploymentName,
		database:       database,
		config:         config,
	}
}

// SetTracker sets the metric tracker for staleness detection
// When set, the Collect method will process metrics through the tracker
func (c *Collector) SetTracker(tracker *MetricTracker) {
	c.tracker = tracker
}

// Collect generates structured metrics data
func (c *Collector) Collect() (*MetricsData, error) {
	data := &MetricsData{
		Families: make([]MetricFamily, 0),
	}

	// Collect deployment metric if enabled
	if c.config.DeploymentEnabled {
		family, err := c.collectDeploymentMetric()
		if err != nil {
			return nil, fmt.Errorf("failed to collect deployment metric: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Collect scanned container metrics if enabled
	if c.config.ScannedContainersEnabled && c.database != nil {
		family, err := c.collectScannedContainerMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect scanned container metrics: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Fetch vulnerability data once for all vulnerability metrics (performance optimization)
	var vulnData []database.ContainerVulnerability
	needsVulnData := c.database != nil && (c.config.VulnerabilitiesEnabled ||
		c.config.VulnerabilityExploitedEnabled ||
		c.config.VulnerabilityRiskEnabled)

	if needsVulnData {
		var err error
		vulnData, err = c.database.GetContainerVulnerabilities()
		if err != nil {
			return nil, fmt.Errorf("failed to get container vulnerabilities: %w", err)
		}
	}

	// Collect vulnerability metrics if enabled
	if c.config.VulnerabilitiesEnabled && c.database != nil {
		family := c.collectVulnerabilityMetrics(vulnData)
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability exploited metrics if enabled
	if c.config.VulnerabilityExploitedEnabled && c.database != nil {
		family := c.collectVulnerabilityExploitedMetrics(vulnData)
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability risk metrics if enabled
	if c.config.VulnerabilityRiskEnabled && c.database != nil {
		family := c.collectVulnerabilityRiskMetrics(vulnData)
		data.Families = append(data.Families, family)
	}

	// Collect image scan status metrics if enabled
	if c.config.ImageScanStatusEnabled && c.database != nil {
		family, err := c.collectImageScanStatusMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect image scan status metrics: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Process through tracker for staleness detection if configured
	if c.tracker != nil {
		data = c.tracker.ProcessMetrics(data)
	}

	return data, nil
}

// collectDeploymentMetric generates the bjorn2scan_deployment metric
func (c *Collector) collectDeploymentMetric() (MetricFamily, error) {
	deploymentName := c.infoProvider.GetDeploymentName()
	deploymentType := c.infoProvider.GetDeploymentType()
	version := c.infoProvider.GetVersion()
	deploymentIP := c.infoProvider.GetDeploymentIP()
	consoleURL := c.infoProvider.GetConsoleURL()
	grypeDBBuilt := c.infoProvider.GetGrypeDBBuilt()

	labels := map[string]string{
		"deployment_uuid":    c.deploymentUUID,
		"deployment_name":    deploymentName,
		"deployment_type":    deploymentType,
		"bjorn2scan_version": version,
	}

	// Only include deployment_ip if not empty
	if deploymentIP != "" {
		labels["deployment_ip"] = deploymentIP
	}

	// Only include deployment_console if not empty
	if consoleURL != "" {
		labels["deployment_console"] = consoleURL
	}

	// Only include grype_db_built if not empty
	if grypeDBBuilt != "" {
		labels["grype_db_built"] = grypeDBBuilt
	}

	return MetricFamily{
		Name: "bjorn2scan_deployment",
		Help: "Bjorn2scan deployment information",
		Type: "gauge",
		Metrics: []MetricPoint{
			{
				Labels: labels,
				Value:  1,
			},
		},
	}, nil
}

// collectScannedContainerMetrics generates bjorn2scan_scanned_container metrics for all scanned containers
func (c *Collector) collectScannedContainerMetrics() (MetricFamily, error) {
	containers, err := c.database.GetScannedContainers()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get scanned containers: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(containers))

	for _, ctr := range containers {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, ctr.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, ctr.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, ctr.Namespace, ctr.Reference)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, ctr.Namespace, ctr.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, ctr.Namespace, ctr.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, ctr.Namespace, ctr.Pod, ctr.Name)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                         c.deploymentUUID,
				"deployment_name":                         c.deploymentName,
				"deployment_uuid_host_name":               deploymentUUIDHostName,
				"deployment_uuid_namespace":               deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":         deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":  deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":           deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                               ctr.NodeName,
				"namespace":                               ctr.Namespace,
				"pod":                                     ctr.Pod,
				"container":                               ctr.Name,
				"distro":                                  ctr.OSName,
				"architecture":                            ctr.Architecture,
				"image_reference":                         ctr.Reference,
				"image_digest":                            ctr.Digest,
				"instance_type":                           "CONTAINER",
			},
			Value: 1,
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_scanned_container",
		Help:    "Bjorn2scan scanned container information",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}

// collectVulnerabilityMetrics generates bjorn2scan_vulnerability metrics for all vulnerabilities in running containers
func (c *Collector) collectVulnerabilityMetrics(vulns []database.ContainerVulnerability) MetricFamily {
	metrics := make([]MetricPoint, 0, len(vulns))

	for _, v := range vulns {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, v.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, v.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Reference)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod, v.Name)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, v.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                         c.deploymentUUID,
				"deployment_name":                         c.deploymentName,
				"deployment_uuid_host_name":               deploymentUUIDHostName,
				"deployment_uuid_namespace":               deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":         deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":  deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":           deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                               v.NodeName,
				"namespace":                               v.Namespace,
				"pod":                                     v.Pod,
				"container":                               v.Name,
				"distro":                                  v.OSName,
				"image_reference":                         v.Reference,
				"image_digest":                            v.Digest,
				"instance_type":                           "CONTAINER",
				"severity":                                v.Severity,
				"vulnerability":                           v.CVEID,
				"vulnerability_id":                        vulnerabilityID,
				"package_name":                            v.PackageName,
				"package_version":                         v.PackageVersion,
				"fix_status":                              v.FixStatus,
				"fixed_version":                           v.FixedVersion,
			},
			Value: float64(v.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability",
		Help:    "Bjorn2scan vulnerability information for running containers",
		Type:    "gauge",
		Metrics: metrics,
	}
}

// collectVulnerabilityExploitedMetrics generates bjorn2scan_vulnerability_exploited metrics for vulnerabilities with known exploits
// Only includes vulnerabilities where known_exploited > 0 (CISA KEV catalog entries)
func (c *Collector) collectVulnerabilityExploitedMetrics(vulns []database.ContainerVulnerability) MetricFamily {
	metrics := make([]MetricPoint, 0, len(vulns))

	for _, v := range vulns {
		// Only include vulnerabilities with known exploits
		if v.KnownExploited == 0 {
			continue
		}

		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, v.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, v.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Reference)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod, v.Name)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, v.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                         c.deploymentUUID,
				"deployment_name":                         c.deploymentName,
				"deployment_uuid_host_name":               deploymentUUIDHostName,
				"deployment_uuid_namespace":               deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":         deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":  deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":           deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                               v.NodeName,
				"namespace":                               v.Namespace,
				"pod":                                     v.Pod,
				"container":                               v.Name,
				"distro":                                  v.OSName,
				"image_reference":                         v.Reference,
				"image_digest":                            v.Digest,
				"instance_type":                           "CONTAINER",
				"severity":                                v.Severity,
				"vulnerability":                           v.CVEID,
				"vulnerability_id":                        vulnerabilityID,
				"package_name":                            v.PackageName,
				"package_version":                         v.PackageVersion,
				"fix_status":                              v.FixStatus,
				"fixed_version":                           v.FixedVersion,
			},
			Value: float64(v.KnownExploited * v.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability_exploited",
		Help:    "Bjorn2scan known exploited vulnerabilities (CISA KEV) in running containers",
		Type:    "gauge",
		Metrics: metrics,
	}
}

// collectVulnerabilityRiskMetrics generates bjorn2scan_vulnerability_risk metrics for all vulnerabilities in running containers
// Uses risk field (float) to provide risk scores for each vulnerability
func (c *Collector) collectVulnerabilityRiskMetrics(vulns []database.ContainerVulnerability) MetricFamily {
	metrics := make([]MetricPoint, 0, len(vulns))

	for _, v := range vulns {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, v.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, v.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Reference)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, v.Namespace, v.Pod, v.Name)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, v.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                         c.deploymentUUID,
				"deployment_name":                         c.deploymentName,
				"deployment_uuid_host_name":               deploymentUUIDHostName,
				"deployment_uuid_namespace":               deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":         deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":  deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":           deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                               v.NodeName,
				"namespace":                               v.Namespace,
				"pod":                                     v.Pod,
				"container":                               v.Name,
				"distro":                                  v.OSName,
				"image_reference":                         v.Reference,
				"image_digest":                            v.Digest,
				"instance_type":                           "CONTAINER",
				"severity":                                v.Severity,
				"vulnerability":                           v.CVEID,
				"vulnerability_id":                        vulnerabilityID,
				"package_name":                            v.PackageName,
				"package_version":                         v.PackageVersion,
				"fix_status":                              v.FixStatus,
				"fixed_version":                           v.FixedVersion,
			},
			Value: v.Risk * float64(v.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability_risk",
		Help:    "Bjorn2scan vulnerability risk scores for running containers",
		Type:    "gauge",
		Metrics: metrics,
	}
}

// collectImageScanStatusMetrics generates bjorn2scan_image_scan_status metrics
// showing the count of running images by scan status
func (c *Collector) collectImageScanStatusMetrics() (MetricFamily, error) {
	statusCounts, err := c.database.GetImageScanStatusCounts()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get image scan status counts: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(statusCounts))

	for _, sc := range statusCounts {
		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid": c.deploymentUUID,
				"scan_status":     sc.Status,
			},
			Value: float64(sc.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_image_scan_status",
		Help:    "Count of running container images by scan status",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}
