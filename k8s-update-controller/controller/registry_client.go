package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// RegistryClient handles OCI registry operations
type RegistryClient struct {
	chartRegistry string
}

// NewRegistryClient creates a new registry client
func NewRegistryClient(chartRegistry string) *RegistryClient {
	return &RegistryClient{
		chartRegistry: chartRegistry,
	}
}

// ListVersions lists all available chart versions from the OCI registry
func (rc *RegistryClient) ListVersions(ctx context.Context) ([]string, error) {
	// Parse OCI registry URL (e.g., "oci://ghcr.io/bvboe/b2s-go/bjorn2scan")
	registryURL := strings.TrimPrefix(rc.chartRegistry, "oci://")

	// Parse as OCI reference
	ref, err := name.ParseReference(registryURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL: %w", err)
	}

	// List tags
	tags, err := remote.List(ref.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	// Filter out non-version tags (like 'latest', 'sha-*')
	versions := []string{}
	for _, tag := range tags {
		// Skip non-semantic version tags
		if tag == "latest" || strings.HasPrefix(tag, "sha-") {
			continue
		}
		versions = append(versions, tag)
	}

	return versions, nil
}

// DownloadChart downloads a specific chart version to a temporary directory
func (rc *RegistryClient) DownloadChart(ctx context.Context, version string) (string, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "helm-chart-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Build chart reference
	registryURL := strings.TrimPrefix(rc.chartRegistry, "oci://")
	chartRef := fmt.Sprintf("%s:%s", registryURL, version)

	// Parse reference
	ref, err := name.ParseReference(chartRef)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("invalid chart reference: %w", err)
	}

	// Pull OCI artifact (Helm chart)
	img, err := remote.Image(ref)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to pull chart: %w", err)
	}

	// Get the layers - Helm charts are stored as a single layer
	layers, err := img.Layers()
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to get image layers: %w", err)
	}

	if len(layers) == 0 {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("chart image has no layers")
	}

	// Extract the first layer (contains the chart.tgz)
	layer := layers[0]
	layerReader, err := layer.Compressed()
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to read layer: %w", err)
	}
	defer func() { _ = layerReader.Close() }()

	// Write layer content to file
	chartPath := filepath.Join(tmpDir, "chart.tgz")
	chartFile, err := os.Create(chartPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to create chart file: %w", err)
	}
	defer func() { _ = chartFile.Close() }()

	// Copy layer content to file
	if _, err := chartFile.ReadFrom(layerReader); err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to write chart file: %w", err)
	}

	return chartPath, nil
}

// VerifySignature verifies the cosign signature of a chart
func (rc *RegistryClient) VerifySignature(ctx context.Context, chartPath string, identityRegexp string, oidcIssuer string) error {
	// TODO: Implement cosign verification
	// For now, we'll skip this in the initial implementation
	// This will be added in a follow-up as it requires cosign library integration

	fmt.Println("Note: Signature verification not yet implemented")
	return nil
}
