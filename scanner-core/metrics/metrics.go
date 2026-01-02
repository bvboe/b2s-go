// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

import (
	"fmt"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// InfoProvider provides deployment information for metrics labels
type InfoProvider interface {
	GetDeploymentName() string // hostname for agent, cluster name for k8s
	GetDeploymentType() string // "agent" or "kubernetes"
	GetVersion() string
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

// Collect generates Prometheus metrics in text format
func (c *Collector) Collect() (string, error) {
	var output strings.Builder

	// Collect deployment metric if enabled
	if c.config.DeploymentEnabled {
		deploymentMetric, err := c.collectDeploymentMetric()
		if err != nil {
			return "", fmt.Errorf("failed to collect deployment metric: %w", err)
		}
		output.WriteString(deploymentMetric)
	}

	// Collect scanned instance metrics if enabled
	if c.config.ScannedInstancesEnabled && c.database != nil {
		instanceMetrics, err := c.collectScannedInstanceMetrics()
		if err != nil {
			return "", fmt.Errorf("failed to collect scanned instance metrics: %w", err)
		}
		output.WriteString(instanceMetrics)
	}

	// Collect vulnerability metrics if enabled
	if c.config.VulnerabilitiesEnabled && c.database != nil {
		vulnMetrics, err := c.collectVulnerabilityMetrics()
		if err != nil {
			return "", fmt.Errorf("failed to collect vulnerability metrics: %w", err)
		}
		output.WriteString(vulnMetrics)
	}

	return output.String(), nil
}

// collectDeploymentMetric generates the bjorn2scan_deployment metric
func (c *Collector) collectDeploymentMetric() (string, error) {
	deploymentName := c.infoProvider.GetDeploymentName()
	deploymentType := c.infoProvider.GetDeploymentType()
	version := c.infoProvider.GetVersion()

	labels := fmt.Sprintf(`deployment_uuid="%s",deployment_name="%s",deployment_type="%s",bjorn2scan_version="%s"`,
		escapeLabelValue(c.deploymentUUID),
		escapeLabelValue(deploymentName),
		escapeLabelValue(deploymentType),
		escapeLabelValue(version))

	return fmt.Sprintf("bjorn2scan_deployment{%s} 1\n", labels), nil
}

// collectScannedInstanceMetrics generates bjorn2scan_scanned_instance metrics for all scanned containers
func (c *Collector) collectScannedInstanceMetrics() (string, error) {
	instances, err := c.database.GetScannedContainerInstances()
	if err != nil {
		return "", fmt.Errorf("failed to get scanned container instances: %w", err)
	}

	var output strings.Builder

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

		// Format image tag and digest for labels
		imageTag := instance.Tag
		imageDigest := instance.Digest

		// Build labels
		labels := fmt.Sprintf(
			`deployment_uuid="%s",`+
				`deployment_uuid_host_name="%s",`+
				`deployment_uuid_namespace="%s",`+
				`deployment_uuid_namespace_image="%s",`+
				`deployment_uuid_namespace_image_id="%s",`+
				`deployment_uuid_namespace_pod="%s",`+
				`deployment_uuid_namespace_pod_container="%s",`+
				`host_name="%s",`+
				`namespace="%s",`+
				`pod="%s",`+
				`container="%s",`+
				`distro="%s",`+
				`image_repo="%s",`+
				`image_tag="%s",`+
				`image_digest="%s",`+
				`instance_type="CONTAINER"`,
			escapeLabelValue(c.deploymentUUID),
			escapeLabelValue(deploymentUUIDHostName),
			escapeLabelValue(deploymentUUIDNamespace),
			escapeLabelValue(deploymentUUIDNamespaceImage),
			escapeLabelValue(deploymentUUIDNamespaceImageID),
			escapeLabelValue(deploymentUUIDNamespacePod),
			escapeLabelValue(deploymentUUIDNamespacePodContainer),
			escapeLabelValue(instance.NodeName),
			escapeLabelValue(instance.Namespace),
			escapeLabelValue(instance.Pod),
			escapeLabelValue(instance.Container),
			escapeLabelValue(instance.OSName),
			escapeLabelValue(instance.Repository),
			escapeLabelValue(imageTag),
			escapeLabelValue(imageDigest),
		)

		output.WriteString(fmt.Sprintf("bjorn2scan_scanned_instance{%s} 1\n", labels))
	}

	return output.String(), nil
}

// collectVulnerabilityMetrics generates bjorn2scan_vulnerability metrics for all vulnerabilities in running containers
func (c *Collector) collectVulnerabilityMetrics() (string, error) {
	instances, err := c.database.GetVulnerabilityInstances()
	if err != nil {
		return "", fmt.Errorf("failed to get vulnerability instances: %w", err)
	}

	var output strings.Builder

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

		// Build labels including vulnerability-specific fields
		labels := fmt.Sprintf(
			`deployment_uuid="%s",`+
				`deployment_uuid_host_name="%s",`+
				`deployment_uuid_namespace="%s",`+
				`deployment_uuid_namespace_image="%s",`+
				`deployment_uuid_namespace_image_id="%s",`+
				`deployment_uuid_namespace_pod="%s",`+
				`deployment_uuid_namespace_pod_container="%s",`+
				`host_name="%s",`+
				`namespace="%s",`+
				`pod="%s",`+
				`container="%s",`+
				`distro="%s",`+
				`image_repo="%s",`+
				`image_tag="%s",`+
				`image_digest="%s",`+
				`instance_type="CONTAINER",`+
				`severity="%s",`+
				`vulnerability="%s",`+
				`package_name="%s",`+
				`package_version="%s",`+
				`fix_status="%s",`+
				`fixed_version="%s"`,
			escapeLabelValue(c.deploymentUUID),
			escapeLabelValue(deploymentUUIDHostName),
			escapeLabelValue(deploymentUUIDNamespace),
			escapeLabelValue(deploymentUUIDNamespaceImage),
			escapeLabelValue(deploymentUUIDNamespaceImageID),
			escapeLabelValue(deploymentUUIDNamespacePod),
			escapeLabelValue(deploymentUUIDNamespacePodContainer),
			escapeLabelValue(instance.NodeName),
			escapeLabelValue(instance.Namespace),
			escapeLabelValue(instance.Pod),
			escapeLabelValue(instance.Container),
			escapeLabelValue(instance.OSName),
			escapeLabelValue(instance.Repository),
			escapeLabelValue(instance.Tag),
			escapeLabelValue(instance.Digest),
			escapeLabelValue(instance.Severity),
			escapeLabelValue(instance.CVEID),
			escapeLabelValue(instance.PackageName),
			escapeLabelValue(instance.PackageVersion),
			escapeLabelValue(instance.FixStatus),
			escapeLabelValue(instance.FixedVersion),
		)

		output.WriteString(fmt.Sprintf("bjorn2scan_vulnerability{%s} %d\n", labels, instance.Count))
	}

	return output.String(), nil
}

// escapeLabelValue escapes special characters in Prometheus label values
func escapeLabelValue(value string) string {
	// Escape backslash, newline, and double quote
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
