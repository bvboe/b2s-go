package metrics

import (
	"log"
	"net/http"
)

// Handler returns an HTTP handler for the /metrics endpoint
func Handler(infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig) http.HandlerFunc {
	collector := NewCollector(infoProvider, deploymentUUID, database, config)

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Collect metrics
		data, err := collector.Collect()
		if err != nil {
			log.Printf("Error collecting metrics: %v", err)
			http.Error(w, "Failed to collect metrics", http.StatusInternalServerError)
			return
		}

		// Format as Prometheus text
		metricsText := FormatPrometheus(data)

		// Write response
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(metricsText)); err != nil {
			log.Printf("Error writing metrics response: %v", err)
		}
	}
}

// RegisterMetricsHandler registers the /metrics endpoint on the provided mux
func RegisterMetricsHandler(mux *http.ServeMux, infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig) {
	mux.HandleFunc("/metrics", Handler(infoProvider, deploymentUUID, database, config))
	log.Println("Metrics handler registered at /metrics")
}
