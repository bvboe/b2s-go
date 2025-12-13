# bjorn2scan v2

A Kubernetes-native container and workload scanner. bjorn2scan v2 is a complete reimplementation designed to run inside Kubernetes clusters for continuous security monitoring.

## Overview

bjorn2scan v2 provides:
- Container vulnerability scanning with Grype
- SBOM (Software Bill of Materials) generation using Syft
- Kubernetes workload discovery and monitoring
- RESTful API for integration with existing tools
- Web UI for visualization

## Prerequisites

- Kubernetes cluster (v1.21+)
  - kind, minikube, or any production cluster
- Helm 3.x
- kubectl configured to access your cluster
- Go 1.25+ (for development)

## Installation

### Quick Start with Helm

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

### Using Released Images

When a release is available, you can install using the pre-built container images:

```bash
helm install bjorn2scan ./k8s-scan-server/helm/bjorn2scan \
  --namespace bjorn2scan \
  --create-namespace \
  --set image.repository=ghcr.io/bvboe/b2s-go/k8s-scan-server \
  --set image.tag=v0.1.0
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

- **k8s-scan-server**: Core scanning service that runs inside Kubernetes
  - Container vulnerability scanning
  - SBOM generation
  - Workload discovery
  - RESTful API

Future components (planned):
- Web UI for visualization
- CLI tool for local scanning
- Integration plugins

## Security

### Container Image Signing

Released container images are signed using sigstore/cosign. Verify image signatures:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/k8s-scan-server:v0.1.0
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
