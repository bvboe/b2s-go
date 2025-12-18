package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
)

// DebugSQLHandler handles POST /debug/sql requests to execute read-only SQL queries.
//
// WARNING: This endpoint is for debugging purposes only and should only be enabled
// in development/testing environments. Do not enable in production.
//
// Request format:
//
//	POST /debug/sql
//	Content-Type: application/json
//	{
//	  "query": "SELECT * FROM images LIMIT 10"
//	}
//
// Response format:
//
//	{
//	  "columns": ["column1", "column2"],
//	  "rows": [
//	    {"column1": "value1", "column2": "value2"},
//	    {"column1": "value3", "column2": "value4"}
//	  ],
//	  "row_count": 2
//	}
func DebugSQLHandler(db *database.DB, debugConfig *debug.DebugConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if debug mode is enabled
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON body
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("Warning: failed to close request body: %v", err)
			}
		}()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var request struct {
			Query string `json:"query"`
		}

		if err := json.Unmarshal(body, &request); err != nil {
			log.Printf("Error parsing JSON: %v", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.Query == "" {
			http.Error(w, "Query is required", http.StatusBadRequest)
			return
		}

		// Validate SQL is SELECT only
		valid, err := debug.IsSelectQuery(request.Query)
		if !valid {
			log.Printf("Invalid SQL query rejected: %v", err)
			http.Error(w, fmt.Sprintf("Invalid query: %v", err), http.StatusBadRequest)
			return
		}

		// Execute query
		result, err := db.ExecuteReadOnlyQuery(request.Query)
		if err != nil {
			log.Printf("Error executing query: %v", err)
			http.Error(w, fmt.Sprintf("Query execution failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Build response with columns array to preserve order
		response := map[string]interface{}{
			"columns":   result.Columns,
			"rows":      result.Rows,
			"row_count": len(result.Rows),
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// DebugMetricsHandler handles GET /debug/metrics requests to retrieve performance metrics.
//
// Response format:
//
//	{
//	  "request_count": 123,
//	  "total_duration_ms": 5000,
//	  "queue_depth": 5,
//	  "last_updated": "2025-12-18T00:00:00Z",
//	  "endpoints": {
//	    "/api/images": {
//	      "count": 50,
//	      "total_duration_ms": 2500,
//	      "avg_duration_ms": 50,
//	      "last_access": "2025-12-18T00:00:00Z"
//	    }
//	  }
//	}
func DebugMetricsHandler(debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if debug mode is enabled
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get metrics from debug config
		metrics := debugConfig.GetMetrics()

		// Update queue depth from scan queue
		if scanQueue != nil {
			debugConfig.SetQueueDepth(scanQueue.GetQueueDepth())
			metrics = debugConfig.GetMetrics() // Refresh to get updated queue depth
		}

		// Build response with endpoint details
		endpointDetails := make(map[string]interface{})
		for endpoint, em := range metrics.EndpointMetrics {
			avgDuration := float64(0)
			if em.Count > 0 {
				avgDuration = float64(em.TotalDuration.Milliseconds()) / float64(em.Count)
			}

			endpointDetails[endpoint] = map[string]interface{}{
				"count":             em.Count,
				"total_duration_ms": em.TotalDuration.Milliseconds(),
				"avg_duration_ms":   avgDuration,
				"last_access":       em.LastAccess,
			}
		}

		response := map[string]interface{}{
			"request_count":     metrics.RequestCount,
			"total_duration_ms": metrics.TotalDuration.Milliseconds(),
			"queue_depth":       metrics.QueueDepth,
			"last_updated":      metrics.LastUpdated,
			"endpoints":         endpointDetails,
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// RegisterDebugHandlers registers debug endpoints on the provided mux.
// If debug mode is not enabled, handlers are not registered (zero overhead).
//
// Endpoints:
//   - POST /debug/sql - Execute read-only SQL queries
//   - GET /debug/metrics - Retrieve performance metrics
func RegisterDebugHandlers(mux *http.ServeMux, db *database.DB, debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) {
	if debugConfig == nil || !debugConfig.IsEnabled() {
		// Don't register handlers if debug not enabled
		return
	}

	mux.HandleFunc("/debug/sql", DebugSQLHandler(db, debugConfig))
	mux.HandleFunc("/debug/metrics", DebugMetricsHandler(debugConfig, scanQueue))

	log.Println("Debug handlers registered at /debug/sql and /debug/metrics")
}
