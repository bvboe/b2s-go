# bjorn2scan v2

A Kubernetes-native container and workload scanner. bjorn2scan v2 is a complete reimplementation designed to run inside Kubernetes clusters for continuous security monitoring.

## Overview

bjorn2scan v2 provides:
- **Kubernetes Scanning**: Container vulnerability scanning with Grype
- **SBOM Generation**: Software Bill of Materials using Syft
- **Workload Monitoring**: Kubernetes workload discovery and monitoring
- **Host Agent**: Lightweight agent for scanning Linux hosts outside Kubernetes
- **RESTful API**: Integration with existing tools
- **Web UI**: Visualization (planned)

## Prerequisites

- Kubernetes cluster (v1.21+)
  - kind, minikube, or any production cluster
- Helm 3.x
- kubectl configured to access your cluster
- Go 1.25+ (for development)

## Installation

### bjorn2scan-agent (Host Agent)

For scanning Linux hosts outside of Kubernetes, install the bjorn2scan-agent:

#### One-Liner Installation

**Latest version (recommended):**
```bash
curl -sSfL https://github.com/bvboe/b2s-go/releases/latest/download/install.sh | sudo sh
```

**Specific version (pinned):**
```bash
# Install version 0.1.35 specifically
curl -sSfL https://github.com/bvboe/b2s-go/releases/download/v0.1.35/install.sh | sudo sh
```

Each release includes a version-stamped `install.sh` that defaults to installing that specific version. Use this for reproducible installations or to match a specific release.

**What the installer does:**
- Download the release binary for your platform (amd64 or arm64)
- Verify SHA256 checksums
- Install the binary to `/usr/local/bin/bjorn2scan-agent`
- Create a systemd service
- Start the agent automatically

#### Manual Installation

Download the appropriate binary from [releases](https://github.com/bvboe/b2s-go/releases):

```bash
# Download and extract
curl -sSfL https://github.com/bvboe/b2s-go/releases/download/v0.1.0/bjorn2scan-agent-linux-amd64.tar.gz -o bjorn2scan-agent.tar.gz
tar -xzf bjorn2scan-agent.tar.gz

# Install binary
sudo install -m 755 bjorn2scan-agent-linux-amd64 /usr/local/bin/bjorn2scan-agent

# Verify installation
curl http://localhost:9999/health
curl http://localhost:9999/info
```

#### Agent Management

```bash
# Check status
systemctl status bjorn2scan-agent

# View logs
journalctl -u bjorn2scan-agent -f

# Restart agent
systemctl restart bjorn2scan-agent

# Uninstall (removes all data, logs, and configuration)
curl -sSfL https://github.com/bvboe/b2s-go/releases/latest/download/install.sh | sudo sh -s uninstall
```

**Note:** Uninstall completely removes the agent including all data and logs. Back up any data you need first.

See [bjorn2scan-agent/README.md](bjorn2scan-agent/README.md) for detailed documentation.

---

### Kubernetes Deployment

#### Quick Start with Helm

Install bjorn2scan using Helm:

```bash
# Add the bjorn2scan Helm repository (when available)
# For now, install from source:

# Clone the repository
git clone https://github.com/bvboe/b2s-go.git
cd b2s-go

# Install with default values
helm install bjorn2scan ./k8s-scan-server/helm/bjorn2scan \
  --namespace bjorn2scan \
  --create-namespace
```

### Using Released Helm Chart (Recommended)

When a release is available, you can install directly from the OCI registry:

```bash
helm install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version 0.1.0 \
  --namespace bjorn2scan \
  --create-namespace
```

### Using Downloaded Helm Chart

Alternatively, download the chart from the GitHub release and install locally:

```bash
# Download bjorn2scan-0.1.0.tgz from GitHub releases
helm install bjorn2scan ./bjorn2scan-0.1.0.tgz \
  --namespace bjorn2scan \
  --create-namespace
```

### Verify Installation

Check that the pods are running:

```bash
kubectl get pods -n bjorn2scan
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=bjorn2scan -n bjorn2scan --timeout=120s
```

Test the service:

```bash
# Port-forward to access the service
kubectl port-forward -n bjorn2scan svc/bjorn2scan 8080:8080

# In another terminal
curl http://localhost:8080/health
curl http://localhost:8080/info
```

### K3s and MicroK8s Support

bjorn2scan automatically detects and supports K3s, MicroK8s, and other Kubernetes distributions. The pod-scanner component auto-detects the containerd socket location:

- **Standard Kubernetes**: `/run/containerd/containerd.sock`
- **K3s**: `/run/k3s/containerd/containerd.sock`
- **MicroK8s**: `/var/snap/microk8s/common/run/containerd.sock`

**No additional configuration required** - the Helm chart automatically mounts all socket locations and the pod-scanner selects the correct one.

#### Verify Socket Detection

Check which socket was detected:

```bash
# Standard Kubernetes
kubectl logs -l app.kubernetes.io/component=pod-scanner -n bjorn2scan | grep "Detected containerd socket"

# K3s
kubectl logs -l app.kubernetes.io/component=pod-scanner -n bjorn2scan | grep "Detected containerd socket"

# MicroK8s
microk8s kubectl logs -l app.kubernetes.io/component=pod-scanner -n bjorn2scan | grep "Detected containerd socket"
```

#### Custom Distributions

If your distribution uses a non-standard containerd socket path:

```bash
helm install bjorn2scan ./helm/bjorn2scan \
  --set podScanner.config.containerdSocket="/custom/path/containerd.sock" \
  --namespace bjorn2scan \
  --create-namespace
```

See [helm/bjorn2scan/README.md](helm/bjorn2scan/README.md) for detailed pod-scanner configuration.

## Configuration

Customize your installation by providing your own values:

```bash
# Create a custom values file
cat > my-values.yaml <<EOF
replicaCount: 2

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

service:
  type: LoadBalancer
  port: 80
EOF

# Install with custom values
helm install bjorn2scan ./k8s-scan-server/helm/bjorn2scan \
  -f my-values.yaml \
  --namespace bjorn2scan \
  --create-namespace
```

See `k8s-scan-server/helm/bjorn2scan/values.yaml` for all available configuration options.

## Upgrading

Upgrade an existing installation:

```bash
helm upgrade bjorn2scan ./k8s-scan-server/helm/bjorn2scan \
  --namespace bjorn2scan
```

## Auto-Update

bjorn2scan supports automatic updates to reduce operational overhead and ensure you're always running the latest security fixes.

### Features

- ✅ **Kubernetes**: In-cluster CronJob checks GHCR for new Helm chart versions and auto-upgrades
- ✅ **Agent**: Background service checks GitHub Releases and performs self-updates
- ✅ **Configurable Version Policies**: Control which updates are applied (patch, minor, major)
- ✅ **Version Pinning**: Lock to specific versions for controlled deployments
- ✅ **Signature Verification**: Cosign-based verification of all artifacts
- ✅ **Automatic Rollback**: Health checks with automatic rollback on failure
- ✅ **Manual Control**: API endpoints and kubectl commands for manual operations

### Quick Start

#### Kubernetes Auto-Update

Enable auto-update when installing or upgrading:

```bash
helm upgrade --install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan \
  --create-namespace \
  --set updateController.enabled=true \
  --set updateController.schedule="0 2 * * *"
```

**Configuration example:**

```yaml
updateController:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2am UTC

  config:
    # Version policies
    autoUpdateMinor: true   # Allow 0.1.x → 0.2.x
    autoUpdateMajor: false  # Block 0.x.x → 1.x.x

    # Optional: Pin to specific version
    pinnedVersion: ""       # Empty = auto-update enabled

    # Rollback protection
    rollback:
      enabled: true
      autoRollback: true
      healthCheckDelay: 5m

    # Signature verification
    verification:
      enabled: true
```

**Manual control:**

```bash
# Trigger update check immediately
kubectl create job --from=cronjob/bjorn2scan-update-controller \
  manual-update-$(date +%s) -n bjorn2scan

# Pause auto-updates
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' -n bjorn2scan

# Resume auto-updates
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":false}}' -n bjorn2scan

# View update history
helm history bjorn2scan -n bjorn2scan
```

#### Agent Auto-Update

Enable auto-update by configuring `/etc/bjorn2scan/agent.conf` or `./agent.conf`:

```ini
# Enable automatic updates
auto_update_enabled=true

# Check for updates every 6 hours
auto_update_check_interval=6h

# Version policies
auto_update_minor_versions=true   # Allow 0.1.x → 0.2.x
auto_update_major_versions=false  # Block 0.x.x → 1.x.x

# Optional: Pin to specific version
auto_update_pinned_version=       # Empty = auto-update enabled

# Rollback protection
update_rollback_enabled=true
update_health_check_timeout=60s
```

**Environment variable override:**

```bash
export AUTO_UPDATE_ENABLED=true
export AUTO_UPDATE_CHECK_INTERVAL=12h
```

**Manual control via API:**

```bash
# Check update status
curl http://localhost:9999/api/update/status

# Trigger update check
curl -X POST http://localhost:9999/api/update/trigger

# Pause auto-updates
curl -X POST http://localhost:9999/api/update/pause

# Resume auto-updates
curl -X POST http://localhost:9999/api/update/resume
```

### Version Policies

Control which updates are automatically applied:

| Policy | Configuration | Updates Allowed | Use Case |
|--------|--------------|-----------------|----------|
| **Patch only** | `minor=false, major=false` | 0.1.34 → 0.1.35 | Maximum stability |
| **Minor + Patch** | `minor=true, major=false` | 0.1.34 → 0.2.0 | Recommended default |
| **All updates** | `minor=true, major=true` | 0.9.9 → 1.0.0 | Bleeding edge |

**Version pinning example:**

```yaml
# Kubernetes
updateController:
  config:
    pinnedVersion: "0.1.35"  # Stay on exactly v0.1.35

# Agent (agent.conf)
auto_update_pinned_version=0.1.35
```

### Security

All auto-update operations include:

1. **Signature Verification**: Artifacts are verified using cosign before installation
2. **Checksum Validation**: SHA256 checksums verified for all downloads
3. **Health Checks**: Post-update health verification ensures system stability
4. **Automatic Rollback**: Failed updates automatically rollback to previous version
5. **Audit Logging**: All update operations logged for compliance

### Multi-Environment Strategy

Recommended approach for production deployments:

```yaml
# Development
autoUpdateMinor: true
autoUpdateMajor: true
schedule: "@hourly"        # Get updates quickly

# Staging
autoUpdateMinor: true
autoUpdateMajor: false
schedule: "0 2 * * *"      # Daily at 2am

# Production
pinnedVersion: "0.1.35"    # Manual control
# OR for automatic:
autoUpdateMinor: true
autoUpdateMajor: false
schedule: "0 2 * * 0"      # Weekly on Sunday
maxVersion: "0.2.0"        # Cap at tested version
```

### Documentation

For comprehensive documentation:

- **[Auto-Update User Guide](docs/AUTO_UPDATE.md)** - Complete configuration and usage guide
  - Detailed configuration options for Kubernetes and Agent
  - Version policies and constraints explained
  - Signature verification setup
  - Troubleshooting common issues
  - Best practices for production

- **[Operational Runbooks](docs/RUNBOOKS.md)** - Step-by-step operational procedures
  - Emergency procedures (disable updates, rollback)
  - Routine operations (enable, configure, monitor)
  - Incident response procedures
  - Monitoring and health checks
  - Disaster recovery procedures

### Monitoring

Set up monitoring for auto-update operations:

**Kubernetes:**
```bash
# Check CronJob status
kubectl get cronjob bjorn2scan-update-controller -n bjorn2scan

# View recent update jobs
kubectl get jobs -l app=bjorn2scan-update-controller -n bjorn2scan

# View update logs
kubectl logs -l app=bjorn2scan-update-controller -n bjorn2scan --tail=100

# View Helm release history
helm history bjorn2scan -n bjorn2scan
```

**Agent:**
```bash
# Check update status
curl http://localhost:9999/api/update/status | jq .

# View update logs
sudo journalctl -u bjorn2scan-agent | grep -i update

# Check service logs
sudo tail -f /var/log/bjorn2scan/agent.log
```

### Emergency Procedures

If an update causes issues:

**Kubernetes - Immediate rollback:**
```bash
# Disable auto-updates
kubectl patch cronjob bjorn2scan-update-controller \
  -p '{"spec":{"suspend":true}}' -n bjorn2scan

# Rollback to previous version
helm rollback bjorn2scan -n bjorn2scan

# Verify rollback
helm list -n bjorn2scan
kubectl get pods -n bjorn2scan
```

**Agent - Restore previous version:**
```bash
# Automatic rollback happens if health check fails
# Manual restore if needed:
sudo cp /tmp/bjorn2scan-agent.backup /usr/local/bin/bjorn2scan-agent
sudo chmod +x /usr/local/bin/bjorn2scan-agent
sudo systemctl restart bjorn2scan-agent
```

### Support

For auto-update issues:
- See troubleshooting section in [AUTO_UPDATE.md](docs/AUTO_UPDATE.md)
- Follow procedures in [RUNBOOKS.md](docs/RUNBOOKS.md)
- Report issues on [GitHub Issues](https://github.com/bvboe/b2s-go/issues)

## Uninstallation

Remove bjorn2scan from your cluster:

```bash
helm uninstall bjorn2scan --namespace bjorn2scan
kubectl delete namespace bjorn2scan
```

## Development

For developers working on bjorn2scan v2:

```bash
# Navigate to the k8s-scan-server directory
cd k8s-scan-server

# Run tests
make test

# Build Docker image
make docker-build

# Deploy to local kind cluster
make helm-kind-deploy

# Deploy to local minikube cluster
make helm-minikube-deploy
```

See [k8s-scan-server/README.md](k8s-scan-server/README.md) for detailed development documentation.

## Architecture

bjorn2scan v2 is built as a monorepo with the following components:

### Current Components

- **k8s-scan-server**: Core scanning service that runs inside Kubernetes
  - Container vulnerability scanning
  - SBOM generation
  - Workload discovery
  - RESTful API (port 8080)

- **pod-scanner**: DaemonSet agent for node-level scanning
  - Runs on every Kubernetes node
  - Local container scanning
  - Node resource monitoring (port 8081)

- **bjorn2scan-agent**: Lightweight host agent for Linux servers
  - Runs directly on Linux hosts (outside Kubernetes)
  - HTTP endpoints for health checks and system info (port 9999)
  - Systemd integration
  - Multi-architecture support (amd64, arm64)

### Future Components (Planned)

- Web UI for visualization
- CLI tool for local scanning
- Integration plugins

## Security

### Artifact Signing

**Container Images:**

Released container images are signed using sigstore/cosign:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/k8s-scan-server:0.1.0
```

**Helm Charts:**

Released Helm charts (OCI artifacts) are also signed with cosign:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.0
```

### Vulnerability Scanning

All released images are scanned with Grype and will fail the release pipeline if critical vulnerabilities with fixes are found.

## CI/CD

The project uses GitHub Actions for continuous integration and delivery:

- **CI**: Runs on every push and pull request
  - Unit tests with race detection
  - Code linting (golangci-lint)
  - Security scanning (gosec, Grype)
  - Integration tests on kind and minikube

- **Release**: Triggered on version tags (e.g., `v0.1.0`)
  - Integration tests (must pass before release)
  - Multi-architecture builds (amd64, arm64)
  - Container signing with cosign
  - SBOM generation
  - Helm chart packaging
  - GitHub release creation

## Support

- **Documentation**: See the [k8s-scan-server README](k8s-scan-server/README.md)
- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/bvboe/b2s-go/issues)
- **Design**: See [DESIGN_CONCEPT.MD](DESIGN_CONCEPT.MD) for architectural decisions

## License

Same open source license as bjorn2scan v1.

## Project Status

bjorn2scan v2 is in active development. The current focus is on building the core scanning service with proper Kubernetes integration. The project follows a lab-to-enterprise approach, prioritizing functionality and reliability for security professionals.
