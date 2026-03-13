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
)

// DefaultHostExclusions are the paths to exclude when scanning the host filesystem.
// These exclude container filesystems to avoid double-counting packages that
// are already scanned via container image scanning.
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

// HostSBOMConfig configures the host SBOM handler
type HostSBOMConfig struct {
	// HostPath is the path to the host filesystem (typically /host)
	HostPath string
	// Exclusions are glob patterns to exclude from scanning
	Exclusions []string
	// Timeout is the maximum duration for SBOM generation
	Timeout time.Duration
}

// DefaultHostSBOMConfig returns a default configuration for host scanning
func DefaultHostSBOMConfig() HostSBOMConfig {
	return HostSBOMConfig{
		HostPath:   "/host",
		Exclusions: DefaultHostExclusions,
		Timeout:    10 * time.Minute, // Host scans take longer than container scans
	}
}

// HostSBOMHandler creates an HTTP handler for /host-sbom endpoint
// Generates SBOM for the host filesystem (mounted at /host)
func HostSBOMHandler(cfg HostSBOMConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Host SBOM request received")

		// Set timeout for SBOM generation
		ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
		defer cancel()

		// Configure source with exclusions for container filesystems
		sourceCfg := syft.DefaultGetSourceConfig().
			WithExcludeConfig(source.ExcludeConfig{
				Paths: cfg.Exclusions,
			})

		// Get source for the host filesystem
		log.Printf("Scanning host filesystem: %s (excluding %d patterns)", cfg.HostPath, len(cfg.Exclusions))
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
