// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

import (
	"fmt"
	"strings"
)

// InfoProvider provides deployment information for metrics labels
type InfoProvider interface {
	GetDeploymentName() string // hostname for agent, cluster name for k8s
	GetDeploymentType() string // "agent" or "kubernetes"
	GetVersion() string
}

// Collector collects metrics and formats them for Prometheus
type Collector struct {
	infoProvider   InfoProvider
	deploymentUUID string
}

// NewCollector creates a new metrics collector
func NewCollector(infoProvider InfoProvider, deploymentUUID string) *Collector {
	return &Collector{
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
	}
}

// Collect generates Prometheus metrics in text format
func (c *Collector) Collect() (string, error) {
	var output strings.Builder

	// Single deployment metric with all relevant labels
	deploymentName := c.infoProvider.GetDeploymentName()
	deploymentType := c.infoProvider.GetDeploymentType()
	version := c.infoProvider.GetVersion()

	// Generate metric line
	labels := fmt.Sprintf(`deployment_uuid="%s",deployment_name="%s",deployment_type="%s",bjorn2scan_version="%s"`,
		escapeLabelValue(c.deploymentUUID),
		escapeLabelValue(deploymentName),
		escapeLabelValue(deploymentType),
		escapeLabelValue(version))

	output.WriteString(fmt.Sprintf("bjorn2scan_deployment{%s} 1\n", labels))

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
