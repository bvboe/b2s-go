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

// HandlerWithTracker returns an HTTP handler for the /metrics endpoint with staleness tracking
func HandlerWithTracker(infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig, tracker *MetricTracker) http.HandlerFunc {
	collector := NewCollector(infoProvider, deploymentUUID, database, config)
	if tracker != nil {
		collector.SetTracker(tracker)
	}

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

// HandlerWithNodes returns an HTTP handler for the /metrics endpoint with node metrics support
func HandlerWithNodes(infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig, nodeDatabase NodeDatabaseProvider, nodeConfig NodeCollectorConfig, tracker *MetricTracker) http.HandlerFunc {
	collector := NewCollector(infoProvider, deploymentUUID, database, config)
	if tracker != nil {
		collector.SetTracker(tracker)
	}

	var nodeCollector *NodeCollector
	if nodeDatabase != nil {
		nodeCollector = NewNodeCollector(deploymentUUID, infoProvider.GetDeploymentName(), nodeDatabase, nodeConfig)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Set headers before streaming
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		// Collect and stream image/container metrics
		data, err := collector.Collect()
		if err != nil {
			log.Printf("Error collecting metrics: %v", err)
			http.Error(w, "Failed to collect metrics", http.StatusInternalServerError)
			return
		}

		// Stream image metrics directly to response
		if err := WritePrometheus(w, data); err != nil {
			log.Printf("Error writing image metrics: %v", err)
			return
		}

		// Stream node metrics if enabled
		if nodeCollector != nil {
			// First, write node_scanned metrics (small dataset, use standard collection)
			nodeScannedData, err := nodeCollector.CollectNodeScannedOnly()
			if err != nil {
				log.Printf("Error collecting node scanned metrics: %v", err)
			} else if len(nodeScannedData.Families) > 0 {
				if err := WritePrometheus(w, nodeScannedData); err != nil {
					log.Printf("Error writing node scanned metrics: %v", err)
				}
			}

			// Then stream vulnerability metrics directly from database to response
			// This avoids loading 100k+ vulnerabilities into memory
			streamed, err := nodeCollector.StreamVulnerabilityMetrics(w)
			if err != nil {
				log.Printf("Error streaming node vulnerability metrics: %v", err)
			}

			// Fall back to standard collection if streaming not supported
			if !streamed {
				nodeData, err := nodeCollector.Collect()
				if err != nil {
					log.Printf("Error collecting node metrics: %v", err)
				} else {
					if err := WritePrometheus(w, nodeData); err != nil {
						log.Printf("Error writing node metrics: %v", err)
					}
				}
			}
		}
	}
}

// RegisterMetricsHandler registers the /metrics endpoint on the provided mux
func RegisterMetricsHandler(mux *http.ServeMux, infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig) {
	mux.HandleFunc("/metrics", Handler(infoProvider, deploymentUUID, database, config))
	log.Println("Metrics handler registered at /metrics")
}

// RegisterMetricsHandlerWithTracker registers the /metrics endpoint with staleness tracking
func RegisterMetricsHandlerWithTracker(mux *http.ServeMux, infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig, tracker *MetricTracker) {
	mux.HandleFunc("/metrics", HandlerWithTracker(infoProvider, deploymentUUID, database, config, tracker))
	log.Println("Metrics handler registered at /metrics (with staleness tracking)")
}

// RegisterMetricsHandlerWithNodes registers the /metrics endpoint with node metrics support
func RegisterMetricsHandlerWithNodes(mux *http.ServeMux, infoProvider InfoProvider, deploymentUUID string, database DatabaseProvider, config CollectorConfig, nodeDatabase NodeDatabaseProvider, nodeConfig NodeCollectorConfig, tracker *MetricTracker) {
	mux.HandleFunc("/metrics", HandlerWithNodes(infoProvider, deploymentUUID, database, config, nodeDatabase, nodeConfig, tracker))
	log.Println("Metrics handler registered at /metrics (with node metrics)")
}
