package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"
	"github.com/bvboe/b2s-go/sbom-generator-shared/exclusions"
)

// HostSBOMConfig configures the host SBOM handler
type HostSBOMConfig struct {
	// HostPath is the path to the host filesystem (typically /host)
	HostPath string
	// Timeout is the maximum duration for SBOM generation
	Timeout time.Duration
	// ExtraExclusions are additional exclusion patterns to add to defaults
	ExtraExclusions []string
	// AutoDetectNFS enables auto-detection of network filesystem mounts
	AutoDetectNFS bool
	// ExtraNetworkFSTypes are additional network FS types to detect
	ExtraNetworkFSTypes []string
}

// DefaultHostSBOMConfig returns a default configuration for host scanning
func DefaultHostSBOMConfig() HostSBOMConfig {
	return HostSBOMConfig{
		HostPath:            "/host",
		Timeout:             10 * time.Minute, // Host scans take longer than container scans
		ExtraExclusions:     nil,
		AutoDetectNFS:       true,
		ExtraNetworkFSTypes: nil,
	}
}

// BuildExclusions builds the complete list of exclusions based on config.
func (cfg *HostSBOMConfig) BuildExclusions() []string {
	excCfg := exclusions.HostExclusionConfig{
		ExtraExclusions:     cfg.ExtraExclusions,
		AutoDetectNFS:       cfg.AutoDetectNFS,
		ExtraNetworkFSTypes: cfg.ExtraNetworkFSTypes,
		HostPrefix:          cfg.HostPath,
	}
	result, err := exclusions.BuildExclusions(excCfg)
	if err != nil {
		log.Printf("Warning: failed to detect network mounts: %v", err)
	}
	return result
}

// HostSBOMHandler creates an HTTP handler for /host-sbom endpoint
// Generates SBOM for the host filesystem (mounted at /host)
func HostSBOMHandler(cfg HostSBOMConfig) http.HandlerFunc {
	// Build exclusions once at handler creation time
	exclusionPatterns := cfg.BuildExclusions()

	// Log exclusion configuration for debugging
	log.Printf("Host SBOM exclusion config: autoDetectNFS=%v, extraExclusions=%d, extraNetworkFSTypes=%d",
		cfg.AutoDetectNFS, len(cfg.ExtraExclusions), len(cfg.ExtraNetworkFSTypes))
	log.Printf("Host SBOM handler configured with %d exclusion patterns:", len(exclusionPatterns))
	for _, pattern := range exclusionPatterns {
		log.Printf("  - %s", pattern)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Host SBOM request received")

		// Set timeout for SBOM generation
		ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
		defer cancel()

		// Configure source with exclusions for container filesystems
		sourceCfg := syft.DefaultGetSourceConfig().
			WithExcludeConfig(source.ExcludeConfig{
				Paths: exclusionPatterns,
			})

		// Get source for the host filesystem
		log.Printf("Scanning host filesystem: %s (excluding %d patterns)", cfg.HostPath, len(exclusionPatterns))
		src, err := syft.GetSource(ctx, cfg.HostPath, sourceCfg)
		if err != nil {
			log.Printf("Error getting source for host filesystem: %v", err)
			http.Error(w, "Failed to access host filesystem", http.StatusInternalServerError)
			return
		}

		// Ensure cleanup of source
		defer func() {
			if cleanupErr := src.Close(); cleanupErr != nil {
				log.Printf("Warning: failed to cleanup source: %v", cleanupErr)
			}
		}()

		// Create SBOM from the source
		sbomCfg := syft.DefaultCreateSBOMConfig()
		sbomCfg.Search.Scope = source.AllLayersScope

		s, err := syft.CreateSBOM(ctx, src, sbomCfg)
		if err != nil {
			log.Printf("Error creating SBOM for host filesystem: %v", err)

			// Check if it's a timeout
			if ctx.Err() == context.DeadlineExceeded {
				http.Error(w, "Host SBOM generation timed out", http.StatusGatewayTimeout)
				return
			}

			http.Error(w, "Failed to generate host SBOM", http.StatusInternalServerError)
			return
		}

		// Encode to syft JSON format
		encoder := syftjson.NewFormatEncoder()
		sbomBytes, err := format.Encode(*s, encoder)
		if err != nil {
			log.Printf("Error encoding host SBOM to JSON: %v", err)
			http.Error(w, "Failed to encode host SBOM", http.StatusInternalServerError)
			return
		}

		// Get node name for logging
		nodeName := r.Header.Get("X-Node-Name")
		if nodeName == "" {
			nodeName = "unknown"
		}

		// Create filename for download
		filename := fmt.Sprintf("host-sbom_%s.json", nodeName)

		// Set headers for JSON download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sbomBytes)))

		// Write SBOM data
		if _, err := w.Write(sbomBytes); err != nil {
			log.Printf("Error writing host SBOM response: %v", err)
		} else {
			log.Printf("Successfully served host SBOM for node %s (%d bytes, %d packages)",
				nodeName, len(sbomBytes), s.Artifacts.Packages.PackageCount())
		}
	}
}
