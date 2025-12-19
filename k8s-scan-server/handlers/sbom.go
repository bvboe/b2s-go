package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/bvboe/b2s-go/k8s-scan-server/podscanner"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"k8s.io/client-go/kubernetes"
)

// SBOMDownloadWithRoutingHandler creates an HTTP handler for /api/sbom/{digest} endpoint
// This handler first tries to get SBOM from database, then falls back to routing
// the request to a pod-scanner instance on the node that has the image.
//
// SBOM Caching Behavior:
// - SBOMs generated through the scan queue workflow are automatically cached in the database
//   (see scanner-core/scanning/queue.go processJob method)
// - Direct API requests that fetch SBOMs from pod-scanner are ALSO cached (see line 91-99 below)
// - This means: First API request generates SBOM (2-5s), subsequent requests are instant (<50ms)
// - Benefits: Reduced latency for repeated API calls and lower pod-scanner load
func SBOMDownloadWithRoutingHandler(db *database.DB, clientset kubernetes.Interface, podScannerClient *podscanner.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 10 { // "/api/sbom/" is 10 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[10:] // Remove "/api/sbom/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Normalize digest (ensure sha256: prefix)
		if !strings.HasPrefix(digest, "sha256:") && len(digest) == 64 {
			digest = "sha256:" + digest
		}

		log.Printf("SBOM request for digest: %s", digest)

		// Try to get SBOM from database first (cached/pre-generated SBOMs)
		sbomData, err := db.GetSBOM(digest)
		if err == nil && len(sbomData) > 0 {
			log.Printf("Serving SBOM from database cache for %s", digest)
			writeSBOMResponse(w, sbomData, digest)
			return
		}

		// SBOM not in database, route to pod-scanner
		log.Printf("SBOM not in database, routing to pod-scanner for %s", digest)

		// Find which node has this image
		instance, err := db.GetFirstInstanceForImage(digest)
		if err != nil {
			log.Printf("Failed to find instance for image %s: %v", digest, err)
			http.Error(w, "Image not found in cluster", http.StatusNotFound)
			return
		}

		if instance.NodeName == "" {
			log.Printf("Image %s has no node name (might be from agent)", digest)
			http.Error(w, "Image not available on any cluster node", http.StatusNotFound)
			return
		}

		log.Printf("Routing SBOM request to node: %s (runtime=%s)", instance.NodeName, instance.ContainerRuntime)

		// Request SBOM from pod-scanner on that node
		sbomData, err = podScannerClient.GetSBOMFromNode(r.Context(), clientset, instance.NodeName, digest)
		if err != nil {
			log.Printf("Failed to get SBOM from pod-scanner on node %s: %v", instance.NodeName, err)

			// Check if it's a context timeout
			if r.Context().Err() == context.DeadlineExceeded {
				http.Error(w, "SBOM generation timed out", http.StatusGatewayTimeout)
				return
			}

			http.Error(w, "Failed to generate SBOM", http.StatusInternalServerError)
			return
		}

		// Cache the SBOM for future requests (reduces latency and pod-scanner load)
		// Note: SBOMs from the scan queue workflow are also cached (see queue.go)
		if err := db.StoreSBOM(digest, sbomData); err != nil {
			log.Printf("Warning: Failed to cache SBOM for %s: %v", digest, err)
		} else {
			log.Printf("Cached SBOM for %s (%d bytes)", digest, len(sbomData))
		}

		log.Printf("Successfully retrieved SBOM from pod-scanner (node=%s, size=%d bytes)", instance.NodeName, len(sbomData))
		writeSBOMResponse(w, sbomData, digest)
	}
}

// writeSBOMResponse writes SBOM data to HTTP response with appropriate headers
func writeSBOMResponse(w http.ResponseWriter, sbomData []byte, digest string) {
	// Create a safe filename from digest
	filename := strings.ReplaceAll(digest, ":", "_")
	if len(filename) > 20 {
		filename = filename[:7] + "_" + filename[7:19]
	}
	filename += ".json"

	// Set headers for file download
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sbom_%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sbomData)))

	// Write SBOM data
	if _, err := w.Write(sbomData); err != nil {
		log.Printf("Error writing SBOM response: %v", err)
	}
}
