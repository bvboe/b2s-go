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
	// Build the image reference using repository:tag format only
	// We explicitly avoid digest-based references to prevent any pull attempts from registries
	// Since we only scan locally running containers, repository:tag is always available
	imageRef := fmt.Sprintf("%s:%s", image.Repository, image.Tag)

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
