# Prometheus Metrics Implementation

## Overview

This document describes the Prometheus metrics endpoint implementation for bjorn2scan, enabling monitoring and alerting on vulnerability data.

## Metrics Endpoint

- **Path**: `/metrics`
- **Format**: Prometheus text exposition format
- **Access**: Public (no authentication required by default)

## Metrics Exposed

### 1. Container Instance Metrics

#### `bjorn2scan_scanned_instances`
Gauge metric indicating scanned container instances (value always 1 per instance).

**Labels**:
- `cluster_name`: Cluster identifier (hostname for agent, cluster name for k8s)
- `namespace`: Kubernetes namespace (or "default" for Docker containers)
- `pod_name`: Pod name (or "standalone" for Docker containers)
- `container_name`: Container name
- `image`: Full image reference (repository:tag)
- `image_id`: Image digest (SHA256)
- `distro_name`: Operating system distribution (e.g., "ubuntu", "alpine")
- `distro_version`: OS version (e.g., "22.04", "3.18")
- `node_name`: Node where container runs
- `container_runtime`: Runtime type (e.g., "docker", "containerd")

**Example**:
```
bjorn2scan_scanned_instances{cluster_name="prod-cluster",namespace="frontend",pod_name="web-app-xyz",container_name="nginx",image="nginx:1.25",image_id="sha256:abc123...",distro_name="debian",distro_version="12",node_name="node-1",container_runtime="containerd"} 1
```

### 2. Deployment Metrics

#### `bjorn2scan_deployment`
Gauge metric providing deployment information (value always 1).

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_name`: Deployment name (hostname for agent, cluster name for k8s)
- `deployment_type`: Type of deployment ("agent" or "kubernetes")
- `bjorn2scan_version`: Version of bjorn2scan
- `deployment_ip`: IP address where scanner runs (primary outbound IP for agent, node IP for k8s). Omitted if unavailable.
- `deployment_console`: URL of the web UI console (e.g., http://192.168.1.10:9999/). Omitted if web UI is disabled or URL cannot be determined.

**Example**:
```
# Agent deployment with web UI enabled
bjorn2scan_deployment{deployment_uuid="abc-123",deployment_name="my-server",deployment_type="agent",bjorn2scan_version="0.1.54",deployment_ip="192.168.1.10",deployment_console="http://192.168.1.10:9999/"} 1

# Kubernetes deployment with ClusterIP service
bjorn2scan_deployment{deployment_uuid="def-456",deployment_name="prod-cluster",deployment_type="kubernetes",bjorn2scan_version="0.1.54",deployment_ip="10.0.1.5",deployment_console="http://bjorn2scan.default.svc.cluster.local:80/"} 1
```

**Configuration**:
- Web UI: Enable/disable via `web_ui_enabled` (agent config) or `scanServer.config.webUIEnabled` (Helm)
- Custom Console URL: Set via `CONSOLE_URL` environment variable or `scanServer.config.consoleURL` (Helm) to override auto-detection

### 3. Container Instance Metrics

#### `bjorn2scan_scanned_instance`
Gauge metric for each scanned container instance (value always 1 per instance).

**Labels**:
- `deployment_uuid`: Unique deployment identifier
- `deployment_uuid_host_name`: Hierarchical label combining deployment UUID and host name
- `deployment_uuid_namespace`: Hierarchical label combining deployment UUID and namespace
- `deployment_uuid_namespace_image`: Hierarchical label for deployment, namespace, and image
- `deployment_uuid_namespace_image_id`: Hierarchical label for deployment, namespace, and image digest
- `deployment_uuid_namespace_pod`: Hierarchical label for deployment, namespace, and pod
- `deployment_uuid_namespace_pod_container`: Full hierarchical label for container instance
- `host_name`: Node where container runs
- `namespace`: Kubernetes namespace (or "default" for Docker containers)
- `pod`: Pod name (or "standalone" for Docker containers)
- `container`: Container name
- `distro`: Operating system distribution
- `image_repo`: Image repository
- `image_tag`: Image tag
- `image_digest`: Image digest (SHA256)
- `instance_type`: Type of instance ("CONTAINER")

**Example**:
```
bjorn2scan_scanned_instance{deployment_uuid="abc-123",host_name="node-1",namespace="frontend",pod="web-app-xyz",container="nginx",distro="debian",image_repo="nginx",image_tag="1.25",image_digest="sha256:abc123..."} 1
```

### 4. Vulnerability Metrics

#### `bjorn2scan_vulnerability`
Gauge metric reporting all vulnerabilities found in running container instances. Value represents the number of vulnerability instances.

**Labels**:
- All labels from `bjorn2scan_scanned_instance` plus:
- `severity`: Vulnerability severity (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability`: CVE ID (e.g., "CVE-2024-1234")
- `vulnerability_id`: Unique vulnerability identifier combining deployment UUID and vulnerability DB ID
- `package_name`: Affected package name
- `package_version`: Affected package version
- `fix_status`: Fix availability ("fixed", "not-fixed", "wont-fix", "unknown")
- `fixed_version`: Version with fix (if available)

**Example**:
```
bjorn2scan_vulnerability{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 2
```

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilitiesEnabled: true`
- Agent config: `metrics_vulnerabilities_enabled=true`
- Environment: `METRICS_VULNERABILITIES_ENABLED=true`

#### `bjorn2scan_vulnerability_exploited`
Gauge metric reporting known exploited vulnerabilities (CISA KEV catalog) in running container instances. Only includes vulnerabilities with known exploits. Value is always 1 (presence indicates exploitation).

**Labels**: Same as `bjorn2scan_vulnerability`

**Example**:
```
bjorn2scan_vulnerability_exploited{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 1
```

**Use Case**: This metric helps prioritize remediation by highlighting vulnerabilities that are actively being exploited in the wild according to CISA's Known Exploited Vulnerabilities catalog.

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilityExploitedEnabled: true`
- Agent config: `metrics_vulnerability_exploited_enabled=true`
- Environment: `METRICS_VULNERABILITY_EXPLOITED_ENABLED=true`

#### `bjorn2scan_vulnerability_risk`
Gauge metric reporting vulnerability risk scores for running container instances. Value represents the risk score (float) for each vulnerability. Includes all vulnerabilities regardless of risk value.

**Labels**: Same as `bjorn2scan_vulnerability`

**Example**:
```
bjorn2scan_vulnerability_risk{deployment_uuid="abc-123",namespace="frontend",pod="web-app",container="nginx",severity="Critical",vulnerability="CVE-2024-1234",package_name="openssl",package_version="3.0.0",fix_status="fixed",fixed_version="3.0.13"} 7.5
```

**Use Case**: This metric provides granular risk assessment based on multiple factors (CVSS, EPSS, exploitability). The risk score helps prioritize remediation efforts with more nuance than severity alone.

**Configuration**:
- Helm: `scanServer.config.metrics.vulnerabilityRiskEnabled: true`
- Agent config: `metrics_vulnerability_risk_enabled=true`
- Environment: `METRICS_VULNERABILITY_RISK_ENABLED=true`

### 3. System Metrics

#### `bjorn2scan_scan_status`
Gauge metric indicating scan status (1 = completed, 0 = pending/failed).

**Labels**:
- `image_id`: Image digest (SHA256)
- `status`: Status value (scanned, pending, failed, scanning)

**Example**:
```
bjorn2scan_scan_status{image_id="sha256:abc123...",status="scanned"} 1
bjorn2scan_scan_status{image_id="sha256:def456...",status="pending"} 1
```

#### `bjorn2scan_images_total`
Gauge metric showing total number of unique images.

**Example**:
```
bjorn2scan_images_total 42
```

#### `bjorn2scan_instances_total`
Gauge metric showing total number of container instances.

**Example**:
```
bjorn2scan_instances_total 156
```

## Implementation Architecture

### Package Structure
```
scanner-core/
  metrics/
    collector.go      # Prometheus collector implementation
    metrics.go        # Metric definitions and registration
    handler.go        # HTTP handler for /metrics endpoint
    metrics_test.go   # Unit tests
```

### Data Flow
1. HTTP request to `/metrics`
2. Handler calls collector's `Collect()` method
3. Collector queries database for current state
4. Metrics are generated with appropriate labels
5. Prometheus text format is written to response

### Performance Considerations
- **Caching**: Metrics are computed on each scrape (no caching by default)
- **Query Optimization**: Uses efficient SQL queries with proper indexes
- **Scrape Interval**: Recommended 30-60 seconds
- **Timeout**: Database queries have 10-second timeout

## Configuration

No additional configuration required. The `/metrics` endpoint is automatically registered when the HTTP server starts.

## Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'bjorn2scan-agent'
    static_configs:
      - targets: ['agent-host:9999']
    scrape_interval: 30s
    scrape_timeout: 10s

  - job_name: 'bjorn2scan-k8s'
    kubernetes_sd_configs:
      - role: service
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_label_app]
        regex: bjorn2scan
        action: keep
```

## Example Prometheus Queries

### Count vulnerabilities by severity
```promql
sum by (severity) (bjorn2scan_vulnerability)
```

### Count containers with critical vulnerabilities
```promql
count(bjorn2scan_vulnerability{severity="Critical"})
```

### Container instances by namespace
```promql
count by (namespace) (bjorn2scan_scanned_instance)
```

### Known exploited vulnerabilities (CISA KEV) by severity
```promql
sum by (severity) (bjorn2scan_vulnerability_exploited > 0)
```

### Containers with actively exploited CVEs
```promql
count by (namespace, pod, container) (bjorn2scan_vulnerability_exploited > 0)
```

### Top 10 most critical exploited vulnerabilities
```promql
topk(10, sum by (vulnerability, severity) (bjorn2scan_vulnerability_exploited{severity="Critical"}))
```

### Average risk score by severity
```promql
avg by (severity) (bjorn2scan_vulnerability_risk)
```

### Highest risk vulnerabilities across all containers
```promql
topk(10, max by (vulnerability, severity) (bjorn2scan_vulnerability_risk))
```

### Containers with high-risk vulnerabilities (risk > 7.0)
```promql
count by (namespace, pod, container) (bjorn2scan_vulnerability_risk > 7.0)
```

### Total risk exposure by namespace
```promql
sum by (namespace) (bjorn2scan_vulnerability_risk)
```

### Deployment info
```promql
bjorn2scan_deployment
```

## Grafana Dashboard

A sample Grafana dashboard is available at `docs/grafana-dashboard.json` (TODO).

## Security Considerations

- Metrics endpoint is unauthenticated by default
- Consider using network policies to restrict access
- Image digests are exposed (consider if this is sensitive in your environment)
- No PII or secrets are exposed in metrics
