package metrics

import (
	"log"
	"net/http"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// Handler returns an HTTP handler for the /metrics endpoint
func Handler(db *database.DB, infoProvider InfoProvider) http.HandlerFunc {
	collector := NewCollector(db, infoProvider)

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Collect metrics
		metrics, err := collector.Collect()
		if err != nil {
			log.Printf("Error collecting metrics: %v", err)
			http.Error(w, "Failed to collect metrics", http.StatusInternalServerError)
			return
		}

		// Write response
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(metrics)); err != nil {
			log.Printf("Error writing metrics response: %v", err)
		}
	}
}

// RegisterMetricsHandler registers the /metrics endpoint on the provided mux
func RegisterMetricsHandler(mux *http.ServeMux, db *database.DB, infoProvider InfoProvider) {
	mux.HandleFunc("/metrics", Handler(db, infoProvider))
	log.Println("Metrics handler registered at /metrics")
}
