package syft

import (
	"context"
	"fmt"
	"log"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"
	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// GenerateSBOM generates an SBOM for a Docker image using syft library
// Returns the SBOM as JSON bytes in syft JSON format
func GenerateSBOM(ctx context.Context, image containers.ImageID) ([]byte, error) {
	// Use the image reference directly - it's already in the correct format (e.g., "nginx:1.21")
	// We explicitly avoid digest-based references to prevent any pull attempts from registries
	// Since we only scan locally running containers, the reference is always available
	imageRef := image.Reference

	log.Printf("Generating SBOM for image: %s", imageRef)

	// Configure source to use Docker daemon exclusively
	// This ensures we ONLY scan locally cached images and never attempt registry pulls
	cfg := syft.DefaultGetSourceConfig().WithSources("docker")

	// Parse the image reference and create a source
	src, err := syft.GetSource(ctx, imageRef, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for image %s: %w", imageRef, err)
	}

	// Ensure cleanup of source
	defer func() {
		if cleanupErr := src.Close(); cleanupErr != nil {
			log.Printf("Warning: failed to cleanup source: %v", cleanupErr)
		}
	}()

	// Create SBOM from the source
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM for %s: %w", imageRef, err)
	}

	// Encode to syft JSON format
	encoder := syftjson.NewFormatEncoder()
	sbomBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM to JSON: %w", err)
	}

	log.Printf("Successfully generated SBOM for %s (%d bytes, %d packages)",
		imageRef, len(sbomBytes), s.Artifacts.Packages.PackageCount())

	return sbomBytes, nil
}

// GenerateSBOMFromImageSource generates SBOM from a pre-created source
// Useful for testing or when source is already available
func GenerateSBOMFromImageSource(ctx context.Context, src source.Source) ([]byte, error) {
	// Create SBOM from the source
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Encode to syft JSON format
	encoder := syftjson.NewFormatEncoder()
	sbomBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM to JSON: %w", err)
	}

	return sbomBytes, nil
}

// DefaultHostExclusions are the paths to exclude when scanning the host filesystem.
// These exclude container filesystems to avoid double-counting packages.
var DefaultHostExclusions = []string{
	"**/snapshots/**",            // containerd snapshots
	"**/rootfs/**",               // containerd rootfs
	"**/overlay2/**",             // docker overlay
	"**/var/lib/kubelet/pods/**", // pod volumes
	"**/var/lib/containerd/**",   // containerd data
	"**/var/lib/docker/**",       // docker data
	"**/var/lib/rancher/**",      // k3s/rancher data
	"**/proc/**",                 // proc filesystem
	"**/sys/**",                  // sys filesystem
	"**/dev/**",                  // device files
	"**/run/**",                  // runtime data
	"**/tmp/**",                  // temporary files
}

// GenerateHostSBOM generates an SBOM for the host filesystem
// Returns the SBOM as JSON bytes in syft JSON format
func GenerateHostSBOM(ctx context.Context) ([]byte, error) {
	hostPath := "/"

	log.Printf("Generating SBOM for host filesystem: %s (excluding %d patterns)", hostPath, len(DefaultHostExclusions))

	// Configure source with exclusions for container filesystems
	cfg := syft.DefaultGetSourceConfig().
		WithExcludeConfig(source.ExcludeConfig{
			Paths: DefaultHostExclusions,
		})

	// Get source for the host filesystem
	src, err := syft.GetSource(ctx, hostPath, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for host filesystem: %w", err)
	}

	// Ensure cleanup of source
	defer func() {
		if cleanupErr := src.Close(); cleanupErr != nil {
			log.Printf("Warning: failed to cleanup source: %v", cleanupErr)
		}
	}()

	// Create SBOM from the source
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create host SBOM: %w", err)
	}

	// Encode to syft JSON format
	encoder := syftjson.NewFormatEncoder()
	sbomBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode host SBOM to JSON: %w", err)
	}

	log.Printf("Successfully generated host SBOM (%d bytes, %d packages)",
		len(sbomBytes), s.Artifacts.Packages.PackageCount())

	return sbomBytes, nil
}
