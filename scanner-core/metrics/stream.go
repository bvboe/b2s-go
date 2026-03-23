package metrics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// familyMeta maps each metric family name to its [help text, metric type].
// Used to write HELP/TYPE headers for stale-NaN lines when a family has no current data.
var familyMeta = map[string][2]string{
	"bjorn2scan_deployment":                    {"Bjorn2scan deployment information", "gauge"},
	"bjorn2scan_image_scanned":                 {"Bjorn2scan scanned container image information", "gauge"},
	"bjorn2scan_image_vulnerability":           {"Bjorn2scan vulnerability information for container images", "gauge"},
	"bjorn2scan_image_vulnerability_risk":      {"Bjorn2scan vulnerability risk scores for container images", "gauge"},
	"bjorn2scan_image_vulnerability_exploited": {"Bjorn2scan known exploited vulnerabilities (CISA KEV) in container images", "gauge"},
	"bjorn2scan_image_scan_status":             {"Count of running container images by scan status", "gauge"},
	"bjorn2scan_node_scanned":                  {"Bjorn2scan scanned node information", "gauge"},
	"bjorn2scan_node_vulnerability":            {"Bjorn2scan vulnerability information for nodes", "gauge"},
	"bjorn2scan_node_vulnerability_risk":       {"Bjorn2scan vulnerability risk scores for nodes", "gauge"},
	"bjorn2scan_node_vulnerability_exploited":  {"Bjorn2scan known exploited vulnerabilities (CISA KEV) on nodes", "gauge"},
}

// StreamMetrics writes all enabled metric families to w in Prometheus text format,
// then emits NaN for any stale metrics from a previous cycle.
//
// Returns the accumulated staleness rows for the caller to persist asynchronously.
// The caller should call staleness.FlushAll(batch, cycleStart) and
// staleness.DeleteExpired(cycleStart) after the HTTP response is flushed, so that
// DB writes do not block the client.
//
// Memory profile: 64KB write buffer + staleness batch proportional to total metric count.
// At current scale (~100k-300k rows × ~200 bytes), this is ~20-60MB — acceptable.
func StreamMetrics(
	w io.Writer,
	info InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	config UnifiedConfig,
	staleRows []database.StalenessRow,
	cycleStart time.Time,
) ([]database.StalenessRow, error) {
	bw := bufio.NewWriterSize(w, 64*1024)
	deploymentName := info.GetDeploymentName()
	cycleStartUnix := cycleStart.Unix()

	// writtenFamilies tracks which families have had HELP+TYPE written.
	// Used to avoid duplicate headers when stale NaN lines reference an already-written family.
	writtenFamilies := make(map[string]bool)

	// batch accumulates staleness rows for the caller to flush after the HTTP response.
	var batch []database.StalenessRow

	// writeHeader writes HELP and TYPE lines for a family exactly once.
	writeHeader := func(name, help, metricType string) error {
		if writtenFamilies[name] {
			return nil
		}
		writtenFamilies[name] = true
		if _, err := fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType); err != nil {
			return err
		}
		return nil
	}

	// appendToBatch queues a staleness row for the current metric point.
	appendToBatch := func(familyName string, labels map[string]string) error {
		labelsJSON, err := json.Marshal(labels)
		if err != nil {
			return fmt.Errorf("failed to marshal labels: %w", err)
		}
		batch = append(batch, database.StalenessRow{
			MetricKey:  generateMetricKey(familyName, labels),
			FamilyName: familyName,
			LabelsJSON: string(labelsJSON),
			// LastSeenUnix is set by FlushAll before writing to DB.
			LastSeenUnix: cycleStartUnix,
		})
		return nil
	}

	// ─── 1. Deployment metric ─────────────────────────────────────────────────
	if config.DeploymentEnabled {
		labels := buildDeploymentLabels(info, deploymentUUID, deploymentName)
		if err := writeHeader("bjorn2scan_deployment", familyMeta["bjorn2scan_deployment"][0], "gauge"); err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(bw, "bjorn2scan_deployment{%s} 1\n", formatLabels(labels)); err != nil {
			return nil, err
		}
		if err := appendToBatch("bjorn2scan_deployment", labels); err != nil {
			return nil, err
		}
	}

	// ─── 2. Image scanned (stream containers) ────────────────────────────────
	if config.ScannedContainersEnabled {
		if err := provider.StreamScannedContainers(func(ctr database.ScannedContainer) error {
			if err := writeHeader("bjorn2scan_image_scanned", familyMeta["bjorn2scan_image_scanned"][0], "gauge"); err != nil {
				return err
			}
			info := containerInfo{
				NodeName:  ctr.NodeName,
				Namespace: ctr.Namespace,
				Pod:       ctr.Pod,
				Name:      ctr.Name,
				Reference: ctr.Reference,
				Digest:    ctr.Digest,
				OSName:    ctr.OSName,
				Arch:      ctr.Architecture,
			}
			labels := buildContainerBaseLabels(deploymentUUID, deploymentName, info)
			if _, err := fmt.Fprintf(bw, "bjorn2scan_image_scanned{%s} 1\n", formatLabels(labels)); err != nil {
				return err
			}
			return appendToBatch("bjorn2scan_image_scanned", labels)
		}); err != nil {
			return nil, fmt.Errorf("streaming scanned containers: %w", err)
		}
	}

	// ─── 3. Image vulnerabilities (3 families, single DB pass) ───────────────
	needsVulns := config.VulnerabilitiesEnabled || config.VulnerabilityExploitedEnabled || config.VulnerabilityRiskEnabled
	if needsVulns {
		if err := provider.StreamContainerVulnerabilities(func(v database.ContainerVulnerability) error {
			labels := buildContainerVulnerabilityLabels(deploymentUUID, deploymentName, v)
			labelsStr := formatLabels(labels)

			if config.VulnerabilitiesEnabled {
				if err := writeHeader("bjorn2scan_image_vulnerability", familyMeta["bjorn2scan_image_vulnerability"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_image_vulnerability{%s} %g\n", labelsStr, float64(v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_image_vulnerability", labels); err != nil {
					return err
				}
			}

			if config.VulnerabilityRiskEnabled {
				if err := writeHeader("bjorn2scan_image_vulnerability_risk", familyMeta["bjorn2scan_image_vulnerability_risk"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_image_vulnerability_risk{%s} %g\n", labelsStr, v.Risk*float64(v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_image_vulnerability_risk", labels); err != nil {
					return err
				}
			}

			if config.VulnerabilityExploitedEnabled && v.KnownExploited > 0 {
				if err := writeHeader("bjorn2scan_image_vulnerability_exploited", familyMeta["bjorn2scan_image_vulnerability_exploited"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_image_vulnerability_exploited{%s} %g\n", labelsStr, float64(v.KnownExploited*v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_image_vulnerability_exploited", labels); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			return nil, fmt.Errorf("streaming container vulnerabilities: %w", err)
		}
	}

	// ─── 4. Image scan status (small, load all at once) ──────────────────────
	if config.ImageScanStatusEnabled {
		statusCounts, err := provider.GetImageScanStatusCounts()
		if err != nil {
			return nil, fmt.Errorf("getting image scan status counts: %w", err)
		}
		for _, sc := range statusCounts {
			if err := writeHeader("bjorn2scan_image_scan_status", familyMeta["bjorn2scan_image_scan_status"][0], "gauge"); err != nil {
				return nil, err
			}
			labels := map[string]string{
				"deployment_uuid": deploymentUUID,
				"scan_status":     sc.Status,
			}
			if _, err := fmt.Fprintf(bw, "bjorn2scan_image_scan_status{%s} %g\n", formatLabels(labels), float64(sc.Count)); err != nil {
				return nil, err
			}
			if err := appendToBatch("bjorn2scan_image_scan_status", labels); err != nil {
				return nil, err
			}
		}
	}

	// ─── 5. Node scanned (small, load all at once) ────────────────────────────
	if config.NodeScannedEnabled {
		nodeList, err := provider.GetScannedNodes()
		if err != nil {
			return nil, fmt.Errorf("getting scanned nodes: %w", err)
		}
		for _, node := range nodeList {
			if err := writeHeader("bjorn2scan_node_scanned", familyMeta["bjorn2scan_node_scanned"][0], "gauge"); err != nil {
				return nil, err
			}
			labels := buildNodeBaseLabels(deploymentUUID, deploymentName, node)
			if _, err := fmt.Fprintf(bw, "bjorn2scan_node_scanned{%s} 1\n", formatLabels(labels)); err != nil {
				return nil, err
			}
			if err := appendToBatch("bjorn2scan_node_scanned", labels); err != nil {
				return nil, err
			}
		}
	}

	// ─── 6. Node vulnerabilities (3 families, single DB pass) ────────────────
	needsNodeVulns := config.NodeVulnerabilitiesEnabled || config.NodeVulnerabilityRiskEnabled || config.NodeVulnerabilityExploitedEnabled
	if needsNodeVulns {
		if err := provider.StreamNodeVulnerabilitiesForMetrics(func(v database.NodeVulnerabilityForMetrics) error {
			labels := buildNodeVulnerabilityLabels(deploymentUUID, deploymentName, v)
			labelsStr := formatLabels(labels)

			if config.NodeVulnerabilitiesEnabled {
				if err := writeHeader("bjorn2scan_node_vulnerability", familyMeta["bjorn2scan_node_vulnerability"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_node_vulnerability{%s} %g\n", labelsStr, float64(v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_node_vulnerability", labels); err != nil {
					return err
				}
			}

			if config.NodeVulnerabilityRiskEnabled {
				if err := writeHeader("bjorn2scan_node_vulnerability_risk", familyMeta["bjorn2scan_node_vulnerability_risk"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_node_vulnerability_risk{%s} %g\n", labelsStr, v.Score*float64(v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_node_vulnerability_risk", labels); err != nil {
					return err
				}
			}

			if config.NodeVulnerabilityExploitedEnabled && v.KnownExploited > 0 {
				if err := writeHeader("bjorn2scan_node_vulnerability_exploited", familyMeta["bjorn2scan_node_vulnerability_exploited"][0], "gauge"); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(bw, "bjorn2scan_node_vulnerability_exploited{%s} %g\n", labelsStr, float64(v.KnownExploited*v.Count)); err != nil {
					return err
				}
				if err := appendToBatch("bjorn2scan_node_vulnerability_exploited", labels); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			return nil, fmt.Errorf("streaming node vulnerabilities: %w", err)
		}
	}

	// ─── 7. Emit NaN for stale metrics ───────────────────────────────────────
	// Group by family so each family header is written at most once.
	staleByFamily := make(map[string][]database.StalenessRow)
	for _, row := range staleRows {
		staleByFamily[row.FamilyName] = append(staleByFamily[row.FamilyName], row)
	}

	// Write NaN lines in a deterministic order (same as streaming order above).
	orderedFamilies := []string{
		"bjorn2scan_deployment",
		"bjorn2scan_image_scanned",
		"bjorn2scan_image_vulnerability",
		"bjorn2scan_image_vulnerability_risk",
		"bjorn2scan_image_vulnerability_exploited",
		"bjorn2scan_image_scan_status",
		"bjorn2scan_node_scanned",
		"bjorn2scan_node_vulnerability",
		"bjorn2scan_node_vulnerability_risk",
		"bjorn2scan_node_vulnerability_exploited",
	}

	for _, familyName := range orderedFamilies {
		rows, ok := staleByFamily[familyName]
		if !ok {
			continue
		}
		meta := familyMeta[familyName]
		if err := writeHeader(familyName, meta[0], meta[1]); err != nil {
			return nil, err
		}
		for _, row := range rows {
			var labels map[string]string
			if err := json.Unmarshal([]byte(row.LabelsJSON), &labels); err != nil {
				log.Warn("skipping stale metric: invalid labels JSON",
					"family", familyName, "metric_key", row.MetricKey, "error", err)
				continue
			}
			if _, err := fmt.Fprintf(bw, "%s{%s} NaN\n", familyName, formatLabels(labels)); err != nil {
				return nil, err
			}
		}
	}

	return batch, bw.Flush()
}

// ─── Label builder standalone functions ──────────────────────────────────────
// These are used by StreamMetrics. The Collector/NodeCollector methods delegate to these.

// buildDeploymentLabels builds the labels for the bjorn2scan_deployment metric.
func buildDeploymentLabels(info InfoProvider, deploymentUUID, deploymentName string) map[string]string {
	deploymentIP := info.GetDeploymentIP()
	consoleURL := info.GetConsoleURL()
	grypeDBBuilt := info.GetGrypeDBBuilt()

	labels := map[string]string{
		"deployment_uuid":    deploymentUUID,
		"deployment_name":    deploymentName,
		"deployment_type":    info.GetDeploymentType(),
		"bjorn2scan_version": info.GetVersion(),
	}
	if deploymentIP != "" {
		labels["deployment_ip"] = deploymentIP
	}
	if consoleURL != "" {
		labels["deployment_console"] = consoleURL
	}
	if grypeDBBuilt != "" {
		labels["grype_db_built"] = grypeDBBuilt
	}
	return labels
}

// buildContainerBaseLabels creates the common label map for container metrics.
func buildContainerBaseLabels(deploymentUUID, deploymentName string, info containerInfo) map[string]string {
	hl := buildHierarchicalLabels(deploymentUUID, info)
	return map[string]string{
		"deployment_uuid":                         deploymentUUID,
		"deployment_name":                         deploymentName,
		"deployment_uuid_host_name":               hl.DeploymentUUIDHostName,
		"deployment_uuid_namespace":               hl.DeploymentUUIDNamespace,
		"deployment_uuid_namespace_image":         hl.DeploymentUUIDNamespaceImage,
		"deployment_uuid_namespace_image_digest":  hl.DeploymentUUIDNamespaceImageDigest,
		"deployment_uuid_namespace_pod":           hl.DeploymentUUIDNamespacePod,
		"deployment_uuid_namespace_pod_container": hl.DeploymentUUIDNamespacePodContainer,
		"host_name":                               info.NodeName,
		"namespace":                               info.Namespace,
		"pod":                                     info.Pod,
		"container":                               info.Name,
		"distro":                                  info.OSName,
		"architecture":                            info.Arch,
		"image_reference":                         info.Reference,
		"image_digest":                            info.Digest,
		"instance_type":                           "CONTAINER",
	}
}

// buildContainerVulnerabilityLabels creates labels for container vulnerability metrics.
func buildContainerVulnerabilityLabels(deploymentUUID, deploymentName string, v database.ContainerVulnerability) map[string]string {
	info := containerInfo{
		NodeName:  v.NodeName,
		Namespace: v.Namespace,
		Pod:       v.Pod,
		Name:      v.Name,
		Reference: v.Reference,
		Digest:    v.Digest,
		OSName:    v.OSName,
	}
	hl := buildHierarchicalLabels(deploymentUUID, info)
	vulnerabilityID := fmt.Sprintf("%s.%d", deploymentUUID, v.VulnID)

	return map[string]string{
		"deployment_uuid":                         deploymentUUID,
		"deployment_name":                         deploymentName,
		"deployment_uuid_host_name":               hl.DeploymentUUIDHostName,
		"deployment_uuid_namespace":               hl.DeploymentUUIDNamespace,
		"deployment_uuid_namespace_image":         hl.DeploymentUUIDNamespaceImage,
		"deployment_uuid_namespace_image_digest":  hl.DeploymentUUIDNamespaceImageDigest,
		"deployment_uuid_namespace_pod":           hl.DeploymentUUIDNamespacePod,
		"deployment_uuid_namespace_pod_container": hl.DeploymentUUIDNamespacePodContainer,
		"host_name":                               info.NodeName,
		"namespace":                               info.Namespace,
		"pod":                                     info.Pod,
		"container":                               info.Name,
		"distro":                                  info.OSName,
		"image_reference":                         info.Reference,
		"image_digest":                            info.Digest,
		"instance_type":                           "CONTAINER",
		"severity":                                v.Severity,
		"vulnerability":                           v.CVEID,
		"vulnerability_id":                        vulnerabilityID,
		"package_name":                            v.PackageName,
		"package_version":                         v.PackageVersion,
		"fix_status":                              v.FixStatus,
		"fixed_version":                           v.FixedVersion,
	}
}

// buildNodeBaseLabels creates the common label map for node metrics.
func buildNodeBaseLabels(deploymentUUID, deploymentName string, node nodes.NodeWithStatus) map[string]string {
	return map[string]string{
		"deployment_uuid": deploymentUUID,
		"deployment_name": deploymentName,
		"node":            node.Name,
		"hostname":        node.Hostname,
		"os_release":      node.OSRelease,
		"kernel_version":  node.KernelVersion,
		"architecture":    node.Architecture,
		"instance_type":   "NODE",
	}
}

// buildNodeVulnerabilityLabels creates labels for node vulnerability metrics.
func buildNodeVulnerabilityLabels(deploymentUUID, deploymentName string, v database.NodeVulnerabilityForMetrics) map[string]string {
	vulnerabilityID := fmt.Sprintf("%s.%d", deploymentUUID, v.VulnID)
	return map[string]string{
		"deployment_uuid":  deploymentUUID,
		"deployment_name":  deploymentName,
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
