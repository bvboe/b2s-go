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

### 2. Vulnerability Metrics

#### `bjorn2scan_vulnerabilities_total`
Gauge metric showing total vulnerability count per image.

**Labels**:
- `image_id`: Image digest (SHA256)
- `severity`: Vulnerability severity (critical, high, medium, low, negligible)

**Example**:
```
bjorn2scan_vulnerabilities_total{image_id="sha256:abc123...",severity="critical"} 5
bjorn2scan_vulnerabilities_total{image_id="sha256:abc123...",severity="high"} 12
```

#### `bjorn2scan_packages_total`
Gauge metric showing total package count per image.

**Labels**:
- `image_id`: Image digest (SHA256)
- `package_type`: Package type (apk, deb, rpm, pypi, npm, etc.)

**Example**:
```
bjorn2scan_packages_total{image_id="sha256:abc123...",package_type="deb"} 145
bjorn2scan_packages_total{image_id="sha256:abc123...",package_type="pypi"} 23
```

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

### Count instances by severity
```promql
sum by (severity) (bjorn2scan_vulnerabilities_total)
```

### Images with critical vulnerabilities
```promql
bjorn2scan_vulnerabilities_total{severity="critical"} > 0
```

### Container instances by namespace
```promql
count by (namespace) (bjorn2scan_scanned_instances)
```

### Unscanned images
```promql
bjorn2scan_scan_status{status="pending"} == 1
```

## Grafana Dashboard

A sample Grafana dashboard is available at `docs/grafana-dashboard.json` (TODO).

## Security Considerations

- Metrics endpoint is unauthenticated by default
- Consider using network policies to restrict access
- Image digests are exposed (consider if this is sensitive in your environment)
- No PII or secrets are exposed in metrics
