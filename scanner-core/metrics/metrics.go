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

// DatabaseProvider provides access to container instance data
type DatabaseProvider interface {
	GetScannedContainerInstances() ([]database.ScannedContainerInstance, error)
	GetVulnerabilityInstances() ([]database.VulnerabilityInstance, error)
	GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error)
}

// CollectorConfig holds configuration for which metrics to collect
type CollectorConfig struct {
	DeploymentEnabled             bool
	ScannedInstancesEnabled       bool
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

	// Collect scanned instance metrics if enabled
	if c.config.ScannedInstancesEnabled && c.database != nil {
		family, err := c.collectScannedInstanceMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect scanned instance metrics: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Fetch vulnerability data once for all vulnerability metrics (performance optimization)
	var vulnInstances []database.VulnerabilityInstance
	needsVulnData := c.database != nil && (c.config.VulnerabilitiesEnabled ||
		c.config.VulnerabilityExploitedEnabled ||
		c.config.VulnerabilityRiskEnabled)

	if needsVulnData {
		var err error
		vulnInstances, err = c.database.GetVulnerabilityInstances()
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability instances: %w", err)
		}
	}

	// Collect vulnerability metrics if enabled
	if c.config.VulnerabilitiesEnabled && c.database != nil {
		family := c.collectVulnerabilityMetrics(vulnInstances)
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability exploited metrics if enabled
	if c.config.VulnerabilityExploitedEnabled && c.database != nil {
		family := c.collectVulnerabilityExploitedMetrics(vulnInstances)
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability risk metrics if enabled
	if c.config.VulnerabilityRiskEnabled && c.database != nil {
		family := c.collectVulnerabilityRiskMetrics(vulnInstances)
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

// collectScannedInstanceMetrics generates bjorn2scan_scanned_instance metrics for all scanned containers
func (c *Collector) collectScannedInstanceMetrics() (MetricFamily, error) {
	instances, err := c.database.GetScannedContainerInstances()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get scanned container instances: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                         c.deploymentUUID,
				"deployment_name":                         c.deploymentName,
				"deployment_uuid_host_name":               deploymentUUIDHostName,
				"deployment_uuid_namespace":               deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":         deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":      deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":           deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                               instance.NodeName,
				"namespace":                               instance.Namespace,
				"pod":                                     instance.Pod,
				"container":                               instance.Container,
				"distro":                                  instance.OSName,
				"image_repo":                              instance.Repository,
				"image_tag":                               instance.Tag,
				"image_digest":                            instance.Digest,
				"instance_type":                           "CONTAINER",
			},
			Value: 1,
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_scanned_instance",
		Help:    "Bjorn2scan scanned container instance information",
		Type:    "gauge",
		Metrics: metrics,
	}, nil
}

// collectVulnerabilityMetrics generates bjorn2scan_vulnerability metrics for all vulnerabilities in running containers
func (c *Collector) collectVulnerabilityMetrics(instances []database.VulnerabilityInstance) MetricFamily {
	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_name":                      c.deploymentName,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":   deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":        deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                            instance.NodeName,
				"namespace":                            instance.Namespace,
				"pod":                                  instance.Pod,
				"container":                            instance.Container,
				"distro":                               instance.OSName,
				"image_repo":                           instance.Repository,
				"image_tag":                            instance.Tag,
				"image_digest":                         instance.Digest,
				"instance_type":                        "CONTAINER",
				"severity":                             instance.Severity,
				"vulnerability":                        instance.CVEID,
				"vulnerability_id":                     vulnerabilityID,
				"package_name":                         instance.PackageName,
				"package_version":                      instance.PackageVersion,
				"fix_status":                           instance.FixStatus,
				"fixed_version":                        instance.FixedVersion,
			},
			Value: float64(instance.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability",
		Help:    "Bjorn2scan vulnerability information for running container instances",
		Type:    "gauge",
		Metrics: metrics,
	}
}

// collectVulnerabilityExploitedMetrics generates bjorn2scan_vulnerability_exploited metrics for vulnerabilities with known exploits
// Only includes vulnerabilities where known_exploited > 0 (CISA KEV catalog entries)
func (c *Collector) collectVulnerabilityExploitedMetrics(instances []database.VulnerabilityInstance) MetricFamily {
	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Only include vulnerabilities with known exploits
		if instance.KnownExploited == 0 {
			continue
		}

		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_name":                      c.deploymentName,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":   deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":        deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                            instance.NodeName,
				"namespace":                            instance.Namespace,
				"pod":                                  instance.Pod,
				"container":                            instance.Container,
				"distro":                               instance.OSName,
				"image_repo":                           instance.Repository,
				"image_tag":                            instance.Tag,
				"image_digest":                         instance.Digest,
				"instance_type":                        "CONTAINER",
				"severity":                             instance.Severity,
				"vulnerability":                        instance.CVEID,
				"vulnerability_id":                     vulnerabilityID,
				"package_name":                         instance.PackageName,
				"package_version":                      instance.PackageVersion,
				"fix_status":                           instance.FixStatus,
				"fixed_version":                        instance.FixedVersion,
			},
			Value: float64(instance.KnownExploited * instance.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability_exploited",
		Help:    "Bjorn2scan known exploited vulnerabilities (CISA KEV) in running container instances",
		Type:    "gauge",
		Metrics: metrics,
	}
}

// collectVulnerabilityRiskMetrics generates bjorn2scan_vulnerability_risk metrics for all vulnerabilities in running containers
// Uses risk field (float) to provide risk scores for each vulnerability
func (c *Collector) collectVulnerabilityRiskMetrics(instances []database.VulnerabilityInstance) MetricFamily {
	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageDigest := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_name":                      c.deploymentName,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_digest":   deploymentUUIDNamespaceImageDigest,
				"deployment_uuid_namespace_pod":        deploymentUUIDNamespacePod,
				"deployment_uuid_namespace_pod_container": deploymentUUIDNamespacePodContainer,
				"host_name":                            instance.NodeName,
				"namespace":                            instance.Namespace,
				"pod":                                  instance.Pod,
				"container":                            instance.Container,
				"distro":                               instance.OSName,
				"image_repo":                           instance.Repository,
				"image_tag":                            instance.Tag,
				"image_digest":                         instance.Digest,
				"instance_type":                        "CONTAINER",
				"severity":                             instance.Severity,
				"vulnerability":                        instance.CVEID,
				"vulnerability_id":                     vulnerabilityID,
				"package_name":                         instance.PackageName,
				"package_version":                      instance.PackageVersion,
				"fix_status":                           instance.FixStatus,
				"fixed_version":                        instance.FixedVersion,
			},
			Value: instance.Risk * float64(instance.Count),
		})
	}

	return MetricFamily{
		Name:    "bjorn2scan_vulnerability_risk",
		Help:    "Bjorn2scan vulnerability risk scores for running container instances",
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
