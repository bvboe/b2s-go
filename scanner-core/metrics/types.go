package metrics

// MetricPoint represents a single metric observation with labels and value
type MetricPoint struct {
	Labels map[string]string
	Value  float64
}

// MetricFamily represents a family of metrics (e.g., all bjorn2scan_deployment metrics)
type MetricFamily struct {
	Name    string        // Metric name (e.g., "bjorn2scan_deployment")
	Help    string        // Help text
	Type    string        // Metric type (e.g., "gauge")
	Metrics []MetricPoint // All metric points in this family
}

// MetricsData holds all metrics to be exported
type MetricsData struct {
	Families []MetricFamily
}
