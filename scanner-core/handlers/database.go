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

// RegisterDatabaseHandlers registers database query endpoints on the provided mux
func RegisterDatabaseHandlers(mux *http.ServeMux, provider DatabaseProvider) {
	mux.HandleFunc("/containers/instances", DatabaseInstancesHandler(provider))
	mux.HandleFunc("/containers/images", DatabaseImagesHandler(provider))
	mux.HandleFunc("/sbom/", SBOMDownloadHandler(provider))
	mux.HandleFunc("/vulnerabilities/", VulnerabilitiesDownloadHandler(provider))
}
