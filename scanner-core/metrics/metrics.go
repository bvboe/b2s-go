// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

import (
	"fmt"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// InfoProvider provides component information for metrics labels
type InfoProvider interface {
	GetClusterName() string
	GetVersion() string
}

// Collector collects metrics from the database and formats them for Prometheus
type Collector struct {
	db           *database.DB
	infoProvider InfoProvider
}

// NewCollector creates a new metrics collector
func NewCollector(db *database.DB, infoProvider InfoProvider) *Collector {
	return &Collector{
		db:           db,
		infoProvider: infoProvider,
	}
}

// Collect generates Prometheus metrics in text format matching kubernetes_vulnerability_* format
func (c *Collector) Collect() (string, error) {
	var output strings.Builder

	// Scanned instances metric
	instanceMetrics, err := c.collectScannedInstances()
	if err != nil {
		return "", fmt.Errorf("failed to collect scanned instances: %w", err)
	}
	output.WriteString(instanceMetrics)

	// Vulnerability results metric (individual CVEs per container)
	vulnMetrics, err := c.collectVulnerabilityResults()
	if err != nil {
		return "", fmt.Errorf("failed to collect vulnerability results: %w", err)
	}
	output.WriteString(vulnMetrics)

	// SBOM metric (individual packages per container)
	sbomMetrics, err := c.collectSBOMPackages()
	if err != nil {
		return "", fmt.Errorf("failed to collect SBOM packages: %w", err)
	}
	output.WriteString(sbomMetrics)

	return output.String(), nil
}

// collectScannedInstances generates kubernetes_vulnerability_scanned_instances metrics
func (c *Collector) collectScannedInstances() (string, error) {
	// Query all instances with their image details
	rows, err := c.db.QueryInstances(`
		SELECT
			i.namespace, i.pod, i.container, i.node_name, i.container_runtime,
			i.repository, i.tag,
			img.digest, COALESCE(img.os_name, 'unknown'), COALESCE(img.os_version, 'unknown')
		FROM container_instances i
		JOIN container_images img ON i.image_id = img.id
		ORDER BY i.namespace, i.pod, i.container
	`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()

	var output strings.Builder
	clusterName := c.infoProvider.GetClusterName()

	for rows.Next() {
		var namespace, pod, container, nodeName, runtime string
		var repository, tag, digest, osName, osVersion string

		if err := rows.Scan(&namespace, &pod, &container, &nodeName, &runtime,
			&repository, &tag, &digest, &osName, &osVersion); err != nil {
			return "", fmt.Errorf("failed to scan instance row: %w", err)
		}

		// Build image reference
		image := fmt.Sprintf("%s:%s", repository, tag)

		// Build composite labels
		clusterNamespace := fmt.Sprintf("%s.%s", clusterName, namespace)
		clusterNamespaceImage := fmt.Sprintf("%s.%s.%s", clusterName, namespace, image)
		clusterNamespaceImageID := fmt.Sprintf("%s.%s.%s", clusterName, namespace, digest)
		clusterNamespacePodName := fmt.Sprintf("%s.%s.%s", clusterName, namespace, pod)
		clusterNamespacePodNameContainerName := fmt.Sprintf("%s.%s.%s.%s", clusterName, namespace, pod, container)

		// Build distro name (combine os_name and os_version if available)
		distroName := osName
		if osVersion != "" && osVersion != "unknown" {
			distroName = fmt.Sprintf("%s %s", osName, osVersion)
		}

		// Generate metric line matching the actual format
		labels := fmt.Sprintf(`cluster_name="%s",instance_type="CONTAINER",cluster_name_namespace="%s",cluster_name_namespace_image="%s",cluster_name_namespace_image_id="%s",cluster_name_namespace_pod_name="%s",cluster_name_namespace_pod_name_container_name="%s",namespace="%s",image="%s",image_id="%s",pod_name="%s",container_name="%s",distro_name="%s"`,
			escapeLabelValue(clusterName),
			escapeLabelValue(clusterNamespace),
			escapeLabelValue(clusterNamespaceImage),
			escapeLabelValue(clusterNamespaceImageID),
			escapeLabelValue(clusterNamespacePodName),
			escapeLabelValue(clusterNamespacePodNameContainerName),
			escapeLabelValue(namespace),
			escapeLabelValue(image),
			escapeLabelValue(digest),
			escapeLabelValue(pod),
			escapeLabelValue(container),
			escapeLabelValue(distroName))

		// Add node_name if available
		if nodeName != "" {
			labels = fmt.Sprintf(`node_name="%s",%s`, escapeLabelValue(nodeName), labels)
		}

		output.WriteString(fmt.Sprintf("kubernetes_vulnerability_scanned_instances{%s} 1\n", labels))
	}

	return output.String(), rows.Err()
}

// collectVulnerabilityResults generates kubernetes_vulnerability_results metrics (individual CVEs per container)
func (c *Collector) collectVulnerabilityResults() (string, error) {
	// Query vulnerabilities with instance details
	rows, err := c.db.QueryVulnerabilityDetails(`
		SELECT
			i.namespace, i.pod, i.container, i.node_name,
			i.repository, i.tag,
			img.digest, COALESCE(img.os_name, 'unknown'), COALESCE(img.os_version, 'unknown'),
			v.cve_id, v.severity, v.fix_status, v.count
		FROM vulnerabilities v
		JOIN container_images img ON v.image_id = img.id
		JOIN container_instances i ON i.image_id = img.id
		ORDER BY i.namespace, i.pod, i.container, v.severity, v.cve_id
	`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()

	var output strings.Builder
	clusterName := c.infoProvider.GetClusterName()

	for rows.Next() {
		var namespace, pod, container, nodeName string
		var repository, tag, digest, osName, osVersion string
		var cveID, severity, fixStatus string
		var count int

		if err := rows.Scan(&namespace, &pod, &container, &nodeName,
			&repository, &tag, &digest, &osName, &osVersion,
			&cveID, &severity, &fixStatus, &count); err != nil {
			return "", fmt.Errorf("failed to scan vulnerability row: %w", err)
		}

		// Build image reference
		image := fmt.Sprintf("%s:%s", repository, tag)

		// Build composite labels
		clusterNamespace := fmt.Sprintf("%s.%s", clusterName, namespace)
		clusterNamespaceImage := fmt.Sprintf("%s.%s.%s", clusterName, namespace, image)
		clusterNamespaceImageID := fmt.Sprintf("%s.%s.%s", clusterName, namespace, digest)
		clusterNamespacePodName := fmt.Sprintf("%s.%s.%s", clusterName, namespace, pod)
		clusterNamespacePodNameContainerName := fmt.Sprintf("%s.%s.%s.%s", clusterName, namespace, pod, container)

		// Build distro name
		distroName := osName
		if osVersion != "" && osVersion != "unknown" {
			distroName = fmt.Sprintf("%s %s", osName, osVersion)
		}

		// Generate metric line
		labels := fmt.Sprintf(`cluster_name="%s",instance_type="CONTAINER",cluster_name_namespace="%s",cluster_name_namespace_image="%s",cluster_name_namespace_image_id="%s",cluster_name_namespace_pod_name="%s",cluster_name_namespace_pod_name_container_name="%s",namespace="%s",image="%s",image_id="%s",pod_name="%s",container_name="%s",distro_name="%s",vulnerability_id="%s",severity="%s",fix_state="%s"`,
			escapeLabelValue(clusterName),
			escapeLabelValue(clusterNamespace),
			escapeLabelValue(clusterNamespaceImage),
			escapeLabelValue(clusterNamespaceImageID),
			escapeLabelValue(clusterNamespacePodName),
			escapeLabelValue(clusterNamespacePodNameContainerName),
			escapeLabelValue(namespace),
			escapeLabelValue(image),
			escapeLabelValue(digest),
			escapeLabelValue(pod),
			escapeLabelValue(container),
			escapeLabelValue(distroName),
			escapeLabelValue(cveID),
			escapeLabelValue(severity),
			escapeLabelValue(fixStatus))

		// Add node_name if available
		if nodeName != "" {
			labels = fmt.Sprintf(`node_name="%s",%s`, escapeLabelValue(nodeName), labels)
		}

		output.WriteString(fmt.Sprintf("kubernetes_vulnerability_results{%s} %d\n", labels, count))
	}

	return output.String(), rows.Err()
}

// collectSBOMPackages generates kubernetes_vulnerability_sbom metrics (individual packages per container)
func (c *Collector) collectSBOMPackages() (string, error) {
	// Query packages with instance details
	rows, err := c.db.QueryPackageDetails(`
		SELECT
			i.namespace, i.pod, i.container, i.node_name,
			i.repository, i.tag,
			img.digest, COALESCE(img.os_name, 'unknown'), COALESCE(img.os_version, 'unknown'),
			p.name, p.version, p.type
		FROM packages p
		JOIN container_images img ON p.image_id = img.id
		JOIN container_instances i ON i.image_id = img.id
		ORDER BY i.namespace, i.pod, i.container, p.name
	`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()

	var output strings.Builder
	clusterName := c.infoProvider.GetClusterName()

	for rows.Next() {
		var namespace, pod, container, nodeName string
		var repository, tag, digest, osName, osVersion string
		var pkgName, pkgVersion, pkgType string

		if err := rows.Scan(&namespace, &pod, &container, &nodeName,
			&repository, &tag, &digest, &osName, &osVersion,
			&pkgName, &pkgVersion, &pkgType); err != nil {
			return "", fmt.Errorf("failed to scan package row: %w", err)
		}

		// Build image reference
		image := fmt.Sprintf("%s:%s", repository, tag)

		// Build composite labels
		clusterNamespace := fmt.Sprintf("%s.%s", clusterName, namespace)
		clusterNamespaceImage := fmt.Sprintf("%s.%s.%s", clusterName, namespace, image)
		clusterNamespaceImageID := fmt.Sprintf("%s.%s.%s", clusterName, namespace, digest)
		clusterNamespacePodName := fmt.Sprintf("%s.%s.%s", clusterName, namespace, pod)
		clusterNamespacePodNameContainerName := fmt.Sprintf("%s.%s.%s.%s", clusterName, namespace, pod, container)

		// Build distro name
		distroName := osName
		if osVersion != "" && osVersion != "unknown" {
			distroName = fmt.Sprintf("%s %s", osName, osVersion)
		}

		// Generate metric line
		labels := fmt.Sprintf(`cluster_name="%s",instance_type="CONTAINER",cluster_name_namespace="%s",cluster_name_namespace_image="%s",cluster_name_namespace_image_id="%s",cluster_name_namespace_pod_name="%s",cluster_name_namespace_pod_name_container_name="%s",namespace="%s",image="%s",image_id="%s",pod_name="%s",container_name="%s",distro_name="%s",name="%s",version="%s",type="%s"`,
			escapeLabelValue(clusterName),
			escapeLabelValue(clusterNamespace),
			escapeLabelValue(clusterNamespaceImage),
			escapeLabelValue(clusterNamespaceImageID),
			escapeLabelValue(clusterNamespacePodName),
			escapeLabelValue(clusterNamespacePodNameContainerName),
			escapeLabelValue(namespace),
			escapeLabelValue(image),
			escapeLabelValue(digest),
			escapeLabelValue(pod),
			escapeLabelValue(container),
			escapeLabelValue(distroName),
			escapeLabelValue(pkgName),
			escapeLabelValue(pkgVersion),
			escapeLabelValue(pkgType))

		// Add node_name if available
		if nodeName != "" {
			labels = fmt.Sprintf(`node_name="%s",%s`, escapeLabelValue(nodeName), labels)
		}

		output.WriteString(fmt.Sprintf("kubernetes_vulnerability_sbom{%s} 1\n", labels))
	}

	return output.String(), rows.Err()
}

// escapeLabelValue escapes special characters in Prometheus label values
func escapeLabelValue(value string) string {
	// Escape backslash, newline, and double quote
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
