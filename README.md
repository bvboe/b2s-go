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

```bash
curl -sSfL https://raw.githubusercontent.com/bvboe/b2s-go/main/bjorn2scan-agent/install.sh | sudo sh
```

This will:
- Download the latest release for your platform (amd64 or arm64)
- Verify checksums
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

# Uninstall
curl -sSfL https://raw.githubusercontent.com/bvboe/b2s-go/main/bjorn2scan-agent/install.sh | sudo sh -s uninstall
```

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
