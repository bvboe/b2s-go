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
}

// DatabaseProvider provides access to container instance data
type DatabaseProvider interface {
	GetScannedContainerInstances() ([]database.ScannedContainerInstance, error)
	GetVulnerabilityInstances() ([]database.VulnerabilityInstance, error)
}

// CollectorConfig holds configuration for which metrics to collect
type CollectorConfig struct {
	DeploymentEnabled        bool
	ScannedInstancesEnabled  bool
	VulnerabilitiesEnabled   bool
	VulnerabilityExploitedEnabled bool
	VulnerabilityRiskEnabled bool
}

// Collector collects metrics and formats them for Prometheus
type Collector struct {
	infoProvider   InfoProvider
	deploymentUUID string
	database       DatabaseProvider
	config         CollectorConfig
}

// NewCollector creates a new metrics collector
func NewCollector(infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig) *Collector {
	return &Collector{
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
		database:       database,
		config:         config,
	}
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

	// Collect vulnerability metrics if enabled
	if c.config.VulnerabilitiesEnabled && c.database != nil {
		family, err := c.collectVulnerabilityMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect vulnerability metrics: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability exploited metrics if enabled
	if c.config.VulnerabilityExploitedEnabled && c.database != nil {
		family, err := c.collectVulnerabilityExploitedMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect vulnerability exploited metrics: %w", err)
		}
		data.Families = append(data.Families, family)
	}

	// Collect vulnerability risk metrics if enabled
	if c.config.VulnerabilityRiskEnabled && c.database != nil {
		family, err := c.collectVulnerabilityRiskMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to collect vulnerability risk metrics: %w", err)
		}
		data.Families = append(data.Families, family)
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
		deploymentUUIDNamespaceImageID := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_id":   deploymentUUIDNamespaceImageID,
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
func (c *Collector) collectVulnerabilityMetrics() (MetricFamily, error) {
	instances, err := c.database.GetVulnerabilityInstances()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get vulnerability instances: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageID := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_id":   deploymentUUIDNamespaceImageID,
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
	}, nil
}

// collectVulnerabilityExploitedMetrics generates bjorn2scan_vulnerability_exploited metrics for vulnerabilities with known exploits
// Only includes vulnerabilities where known_exploited > 0 (CISA KEV catalog entries)
func (c *Collector) collectVulnerabilityExploitedMetrics() (MetricFamily, error) {
	instances, err := c.database.GetVulnerabilityInstances()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get vulnerability instances: %w", err)
	}

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
		deploymentUUIDNamespaceImageID := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_id":   deploymentUUIDNamespaceImageID,
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
	}, nil
}

// collectVulnerabilityRiskMetrics generates bjorn2scan_vulnerability_risk metrics for all vulnerabilities in running containers
// Uses risk field (float) to provide risk scores for each vulnerability
func (c *Collector) collectVulnerabilityRiskMetrics() (MetricFamily, error) {
	instances, err := c.database.GetVulnerabilityInstances()
	if err != nil {
		return MetricFamily{}, fmt.Errorf("failed to get vulnerability instances: %w", err)
	}

	metrics := make([]MetricPoint, 0, len(instances))

	for _, instance := range instances {
		// Generate hierarchical labels
		deploymentUUIDHostName := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.NodeName)
		deploymentUUIDNamespace := fmt.Sprintf("%s.%s", c.deploymentUUID, instance.Namespace)
		deploymentUUIDNamespaceImage := fmt.Sprintf("%s.%s.%s:%s",
			c.deploymentUUID, instance.Namespace, instance.Repository, instance.Tag)
		deploymentUUIDNamespaceImageID := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Digest)
		deploymentUUIDNamespacePod := fmt.Sprintf("%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod)
		deploymentUUIDNamespacePodContainer := fmt.Sprintf("%s.%s.%s.%s",
			c.deploymentUUID, instance.Namespace, instance.Pod, instance.Container)
		vulnerabilityID := fmt.Sprintf("%s.%d", c.deploymentUUID, instance.VulnID)

		metrics = append(metrics, MetricPoint{
			Labels: map[string]string{
				"deployment_uuid":                      c.deploymentUUID,
				"deployment_uuid_host_name":            deploymentUUIDHostName,
				"deployment_uuid_namespace":            deploymentUUIDNamespace,
				"deployment_uuid_namespace_image":      deploymentUUIDNamespaceImage,
				"deployment_uuid_namespace_image_id":   deploymentUUIDNamespaceImageID,
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
	}, nil
}
