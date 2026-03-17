package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// RegisterNodeHandlers registers all node-related HTTP handlers
func RegisterNodeHandlers(mux *http.ServeMux, db *database.DB) {
	mux.HandleFunc("/api/nodes", ListNodesHandler(db))
	mux.HandleFunc("/api/nodes/", NodeDetailHandler(db))
	mux.HandleFunc("/api/summary/by-node", NodeSummaryHandler(db))
	mux.HandleFunc("/api/summary/by-node-distro", NodeDistributionSummaryHandler(db))
	mux.HandleFunc("/api/node-filter-options", NodeFilterOptionsHandler(db))
	mux.HandleFunc("/api/node-vulnerabilities/", NodeVulnerabilityDetailsHandler(db))
	mux.HandleFunc("/api/node-packages/", NodePackageDetailsHandler(db))
}

// ListNodesHandler returns a handler that lists all nodes with their scan status
func ListNodesHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		nodes, err := db.GetAllNodes()
		if err != nil {
			log.Printf("Error getting nodes: %v", err)
			http.Error(w, "Failed to get nodes", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nodes); err != nil {
			log.Printf("Error encoding nodes response: %v", err)
		}
	}
}

// NodeDetailHandler returns a handler for node detail endpoints
// Routes:
//
//	GET /api/nodes/{name} - Get node details
//	GET /api/nodes/{name}/packages - Get node packages
//	GET /api/nodes/{name}/vulnerabilities - Get node vulnerabilities
func NodeDetailHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the path: /api/nodes/{name} or /api/nodes/{name}/{subresource}
		path := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
		if path == "" {
			http.Error(w, "Node name required", http.StatusBadRequest)
			return
		}

		parts := strings.SplitN(path, "/", 2)
		nodeName := parts[0]
		subResource := ""
		if len(parts) > 1 {
			subResource = parts[1]
		}

		var result interface{}
		var err error

		switch subResource {
		case "":
			// GET /api/nodes/{name} - Get node details
			node, getErr := db.GetNode(nodeName)
			if getErr != nil {
				log.Printf("Error getting node %s: %v", nodeName, getErr)
				http.Error(w, "Failed to get node", http.StatusInternalServerError)
				return
			}
			if node == nil {
				http.Error(w, "Node not found", http.StatusNotFound)
				return
			}
			result = node

		case "packages":
			// GET /api/nodes/{name}/packages - Get node packages
			format := r.URL.Query().Get("format")
			if format == "json" {
				// Export raw SBOM JSON (Syft output)
				sbom, sbomErr := db.GetNodeSBOM(nodeName)
				if sbomErr != nil {
					log.Printf("Error getting node SBOM for %s: %v", nodeName, sbomErr)
					http.Error(w, "Failed to get node SBOM", http.StatusInternalServerError)
					return
				}
				if sbom == nil {
					http.Error(w, "SBOM not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"syft-sbom-%s.json\"", nodeName))
				if _, writeErr := w.Write(sbom); writeErr != nil {
					log.Printf("Error writing node SBOM response: %v", writeErr)
				}
				return
			}
			result, err = db.GetNodePackages(nodeName)

		case "vulnerabilities":
			// GET /api/nodes/{name}/vulnerabilities - Get node vulnerabilities
			format := r.URL.Query().Get("format")
			if format == "json" {
				// Export raw vulnerability JSON (Grype output)
				vulns, vulnErr := db.GetNodeVulnerabilitiesRaw(nodeName)
				if vulnErr != nil {
					log.Printf("Error getting node vulnerabilities for %s: %v", nodeName, vulnErr)
					http.Error(w, "Failed to get node vulnerabilities", http.StatusInternalServerError)
					return
				}
				if vulns == nil {
					http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"grype-vulnerabilities-%s.json\"", nodeName))
				if _, writeErr := w.Write(vulns); writeErr != nil {
					log.Printf("Error writing node vulnerabilities response: %v", writeErr)
				}
				return
			}
			result, err = db.GetNodeVulnerabilities(nodeName)

		default:
			http.Error(w, "Unknown subresource", http.StatusNotFound)
			return
		}

		if err != nil {
			log.Printf("Error getting node data for %s/%s: %v", nodeName, subResource, err)
			http.Error(w, "Failed to get node data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("Error encoding node response: %v", err)
		}
	}
}

// parseCommaSeparated splits a comma-separated string into a slice, filtering empty values
func parseCommaSeparated(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// NodeSummaryHandler returns a handler that provides vulnerability summary by node
// Supports filters: osNames, vulnStatuses, packageTypes (comma-separated)
func NodeSummaryHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse filter parameters
		params := r.URL.Query()
		filters := database.NodeSummaryFilters{
			OSNames:      parseCommaSeparated(params.Get("osNames")),
			VulnStatuses: parseCommaSeparated(params.Get("vulnStatuses")),
			PackageTypes: parseCommaSeparated(params.Get("packageTypes")),
		}

		summaries, err := db.GetNodeSummariesFiltered(filters)
		if err != nil {
			log.Printf("Error getting node summaries: %v", err)
			http.Error(w, "Failed to get node summaries", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(summaries); err != nil {
			log.Printf("Error encoding node summaries response: %v", err)
		}
	}
}

// NodeDistributionSummaryHandler returns a handler that provides averaged vulnerability summary by node OS distribution
func NodeDistributionSummaryHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		summaries, err := db.GetNodeDistributionSummary()
		if err != nil {
			log.Printf("Error getting node distribution summary: %v", err)
			http.Error(w, "Failed to get node distribution summary", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(summaries); err != nil {
			log.Printf("Error encoding node distribution summary response: %v", err)
		}
	}
}

// NodeFilterOptionsHandler returns a handler that provides filter options for node-related pages
func NodeFilterOptionsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		options, err := db.GetNodeFilterOptions()
		if err != nil {
			log.Printf("Error getting node filter options: %v", err)
			http.Error(w, "Failed to get node filter options", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(options); err != nil {
			log.Printf("Error encoding node filter options response: %v", err)
		}
	}
}

// NodeVulnerabilityDetailsHandler returns JSON details for a specific node vulnerability
// Route: GET /api/node-vulnerabilities/{id}/details
func NodeVulnerabilityDetailsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse path: /api/node-vulnerabilities/{id}/details
		path := strings.TrimPrefix(r.URL.Path, "/api/node-vulnerabilities/")
		if !strings.HasSuffix(path, "/details") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		idStr := strings.TrimSuffix(path, "/details")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid vulnerability ID", http.StatusBadRequest)
			return
		}

		details, err := db.GetNodeVulnerabilityDetails(id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				http.Error(w, "Vulnerability not found", http.StatusNotFound)
				return
			}
			log.Printf("Error getting node vulnerability details: %v", err)
			http.Error(w, "Failed to get vulnerability details", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(details)); err != nil {
			log.Printf("Error writing vulnerability details response: %v", err)
		}
	}
}

// NodePackageDetailsHandler returns JSON details for a specific node package
// Route: GET /api/node-packages/{id}/details
func NodePackageDetailsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse path: /api/node-packages/{id}/details
		path := strings.TrimPrefix(r.URL.Path, "/api/node-packages/")
		if !strings.HasSuffix(path, "/details") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		idStr := strings.TrimSuffix(path, "/details")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid package ID", http.StatusBadRequest)
			return
		}

		details, err := db.GetNodePackageDetails(id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				http.Error(w, "Package not found", http.StatusNotFound)
				return
			}
			log.Printf("Error getting node package details: %v", err)
			http.Error(w, "Failed to get package details", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(details)); err != nil {
			log.Printf("Error writing package details response: %v", err)
		}
	}
}
