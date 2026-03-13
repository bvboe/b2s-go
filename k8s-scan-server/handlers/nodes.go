package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// NodeHandlerDB defines the interface for node database operations
type NodeHandlerDB interface {
	GetAllNodes() ([]interface{}, error)
	GetNode(name string) (interface{}, error)
	GetNodePackages(name string) (interface{}, error)
	GetNodeVulnerabilities(name string) (interface{}, error)
	GetNodeSummaries() (interface{}, error)
}

// RegisterNodeHandlers registers all node-related HTTP handlers
func RegisterNodeHandlers(mux *http.ServeMux, db *database.DB) {
	mux.HandleFunc("/api/nodes", ListNodesHandler(db))
	mux.HandleFunc("/api/nodes/", NodeDetailHandler(db))
	mux.HandleFunc("/api/summary/by-node", NodeSummaryHandler(db))
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
			result, err = db.GetNodePackages(nodeName)

		case "vulnerabilities":
			// GET /api/nodes/{name}/vulnerabilities - Get node vulnerabilities
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

// NodeSummaryHandler returns a handler that provides vulnerability summary by node
func NodeSummaryHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		summaries, err := db.GetNodeSummaries()
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
