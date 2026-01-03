package metrics

import (
	"fmt"
	"sort"
	"strings"
)

// FormatPrometheus converts structured metrics data to Prometheus text format
func FormatPrometheus(data *MetricsData) string {
	var output strings.Builder

	for _, family := range data.Families {
		// Write HELP line
		output.WriteString(fmt.Sprintf("# HELP %s %s\n", family.Name, family.Help))
		// Write TYPE line
		output.WriteString(fmt.Sprintf("# TYPE %s %s\n", family.Name, family.Type))

		// Write each metric
		for _, metric := range family.Metrics {
			// Format labels
			labels := formatLabels(metric.Labels)
			output.WriteString(fmt.Sprintf("%s{%s} %d\n", family.Name, labels, metric.Value))
		}
	}

	return output.String()
}

// formatLabels converts a label map to Prometheus label string format
// Labels are sorted alphabetically for consistent output
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort label keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build label string
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := escapeLabelValue(labels[k])
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}

	return strings.Join(parts, ",")
}

// escapeLabelValue escapes special characters in Prometheus label values
func escapeLabelValue(value string) string {
	// Escape backslash, newline, and double quote
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
