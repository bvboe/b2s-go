package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// DatabaseProvider defines the interface for querying database contents
type DatabaseProvider interface {
	GetAllInstances() (interface{}, error)
	GetAllImages() (interface{}, error)
	GetAllImageDetails() (interface{}, error)
	GetImageDetails(digest string) (interface{}, error)
	GetPackagesByImage(digest string) (interface{}, error)
	GetVulnerabilitiesByImage(digest string) (interface{}, error)
	GetImageSummary(digest string) (interface{}, error)
	GetSBOM(digest string) ([]byte, error)
	GetVulnerabilities(digest string) ([]byte, error)
}

// DatabaseProviderWithNodeLookup extends DatabaseProvider with node lookup capability
type DatabaseProviderWithNodeLookup interface {
	DatabaseProvider
	GetFirstInstanceForImage(digest string) (NodeInfo, error)
}

// NodeInfo contains information about which node has an image
type NodeInfo struct {
	NodeName         string
	ContainerRuntime string
}

// DatabaseInstancesHandler creates an HTTP handler for /containers/instances endpoint
func DatabaseInstancesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instances, err := provider.GetAllInstances()
		if err != nil {
			log.Printf("Error querying instances: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Wrap response in an object with "instances" key
		response := map[string]interface{}{
			"instances": instances,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding instances response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// DatabaseImagesHandler creates an HTTP handler for /containers/images endpoint
func DatabaseImagesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		images, err := provider.GetAllImages()
		if err != nil {
			log.Printf("Error querying images: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Wrap response in an object with "images" key
		response := map[string]interface{}{
			"images": images,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding images response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// SBOMDownloadHandler creates an HTTP handler for /sbom/{digest} endpoint
// Downloads SBOM as a JSON file
func SBOMDownloadHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /sbom/sha256:abc123...
		path := r.URL.Path
		if len(path) <= 6 { // "/sbom/" is 6 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[6:] // Remove "/sbom/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Get SBOM from database
		sbomData, err := provider.GetSBOM(digest)
		if err != nil {
			log.Printf("Error retrieving SBOM for %s: %v", digest, err)
			http.Error(w, "SBOM not found", http.StatusNotFound)
			return
		}

		// Create a safe filename from digest
		filename := digest
		if len(filename) > 20 {
			// Use shortened version for filename: sha256_abc123.json
			filename = filename[:7] + "_" + filename[7:19]
		}
		filename += ".json"

		// Set headers for file download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"sbom_"+filename+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sbomData)))

		// Write SBOM data
		if _, err := w.Write(sbomData); err != nil {
			log.Printf("Error writing SBOM response: %v", err)
		}
	}
}

// VulnerabilitiesDownloadHandler creates an HTTP handler for /vulnerabilities/{digest} endpoint
// Downloads vulnerability report as a JSON file
func VulnerabilitiesDownloadHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /vulnerabilities/sha256:abc123...
		path := r.URL.Path
		if len(path) <= 17 { // "/vulnerabilities/" is 17 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[17:] // Remove "/vulnerabilities/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Get vulnerabilities from database
		vulnData, err := provider.GetVulnerabilities(digest)
		if err != nil {
			log.Printf("Error retrieving vulnerabilities for %s: %v", digest, err)
			http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
			return
		}

		// Create a safe filename from digest
		filename := digest
		if len(filename) > 20 {
			// Use shortened version for filename: sha256_abc123.json
			filename = filename[:7] + "_" + filename[7:19]
		}
		filename += ".json"

		// Set headers for file download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"vulnerabilities_"+filename+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(vulnData)))

		// Write vulnerability data
		if _, err := w.Write(vulnData); err != nil {
			log.Printf("Error writing vulnerabilities response: %v", err)
		}
	}
}

// ImageDetailsHandler creates an HTTP handler for /api/images endpoint
// Returns detailed image information including vulnerability counts
func ImageDetailsHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		images, err := provider.GetAllImageDetails()
		if err != nil {
			log.Printf("Error querying image details: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"images": images,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding image details response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// ImageDetailHandler creates an HTTP handler for /api/images/{digest} endpoint
// Returns detailed information for a specific image
func ImageDetailHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[12:] // Remove "/api/images/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		details, err := provider.GetImageDetails(digest)
		if err != nil {
			log.Printf("Error querying image details for %s: %v", digest, err)
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(details); err != nil {
			log.Printf("Error encoding image detail response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// PackagesHandler creates an HTTP handler for /api/images/{digest}/packages endpoint
// Returns all packages for a specific image
func PackagesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/images/{digest}/packages
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		// Remove "/api/images/" prefix and "/packages" suffix
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 9 || pathWithoutPrefix[len(pathWithoutPrefix)-9:] != "/packages" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-9]

		packages, err := provider.GetPackagesByImage(digest)
		if err != nil {
			log.Printf("Error querying packages for %s: %v", digest, err)
			http.Error(w, "Packages not found", http.StatusNotFound)
			return
		}

		response := map[string]interface{}{
			"packages": packages,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding packages response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// VulnerabilitiesHandler creates an HTTP handler for /api/images/{digest}/vulnerabilities endpoint
// Returns all vulnerabilities for a specific image
func VulnerabilitiesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/images/{digest}/vulnerabilities
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		// Remove "/api/images/" prefix and "/vulnerabilities" suffix
		pathWithoutPrefix := path[12:]
		// "/vulnerabilities" is 16 characters, not 17!
		if len(pathWithoutPrefix) <= 16 || pathWithoutPrefix[len(pathWithoutPrefix)-16:] != "/vulnerabilities" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-16]

		vulns, err := provider.GetVulnerabilitiesByImage(digest)
		if err != nil {
			log.Printf("Error querying vulnerabilities for %s: %v", digest, err)
			http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
			return
		}

		response := map[string]interface{}{
			"vulnerabilities": vulns,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding vulnerabilities response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// HandlerOverrides allows customization of specific handlers during registration
type HandlerOverrides struct {
	// SBOMHandler optionally overrides the default SBOM download handler
	// Used by k8s-scan-server to route SBOM requests to pod-scanner
	SBOMHandler http.HandlerFunc
	// VulnerabilitiesHandler optionally overrides the default vulnerabilities download handler
	VulnerabilitiesHandler http.HandlerFunc
}

// RegisterDatabaseHandlers registers database query endpoints on the provided mux
// Pass nil for overrides to use all default handlers
func RegisterDatabaseHandlers(mux *http.ServeMux, provider DatabaseProvider, overrides *HandlerOverrides) {
	// Register legacy endpoints
	mux.HandleFunc("/containers/instances", DatabaseInstancesHandler(provider))
	mux.HandleFunc("/containers/images", DatabaseImagesHandler(provider))

	// Register download endpoints with optional overrides
	if overrides != nil && overrides.SBOMHandler != nil {
		mux.HandleFunc("/sbom/", overrides.SBOMHandler)
	} else {
		mux.HandleFunc("/sbom/", SBOMDownloadHandler(provider))
	}

	if overrides != nil && overrides.VulnerabilitiesHandler != nil {
		mux.HandleFunc("/vulnerabilities/", overrides.VulnerabilitiesHandler)
	} else {
		mux.HandleFunc("/vulnerabilities/", VulnerabilitiesDownloadHandler(provider))
	}

	// Register new API endpoints for aggregated data
	mux.HandleFunc("/api/images", ImageDetailsHandler(provider))
	mux.HandleFunc("/api/images/", func(w http.ResponseWriter, r *http.Request) {
		// Route to appropriate handler based on path suffix
		path := r.URL.Path
		// "/api/images/" is 12 characters, not 13!
		if len(path) > 12 {
			pathWithoutPrefix := path[12:]
			if len(pathWithoutPrefix) > 9 && pathWithoutPrefix[len(pathWithoutPrefix)-9:] == "/packages" {
				PackagesHandler(provider)(w, r)
				return
			}
			// "/vulnerabilities" is 16 characters, not 17!
			if len(pathWithoutPrefix) > 16 && pathWithoutPrefix[len(pathWithoutPrefix)-16:] == "/vulnerabilities" {
				VulnerabilitiesHandler(provider)(w, r)
				return
			}
			// Single image detail
			ImageDetailHandler(provider)(w, r)
		}
	})
}
