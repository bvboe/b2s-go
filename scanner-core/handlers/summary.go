package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// ScanStatusCountsHandler creates an HTTP handler for /api/summary/scan-status endpoint
// Returns counts of container images by scan status, excluding statuses with zero count
func ScanStatusCountsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters for filters
		params := r.URL.Query()
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))

		// Build query
		query := buildScanStatusQuery(namespaces, vulnStatuses, packageTypes, osNames)

		// Execute query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error executing scan status query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse results
		type StatusCount struct {
			Status      string `json:"status"`
			Description string `json:"description"`
			SortOrder   int    `json:"sort_order"`
			Count       int64  `json:"count"`
		}

		statusCounts := make([]StatusCount, 0, len(result.Rows))
		for _, row := range result.Rows {
			count := int64(0)
			if val, ok := row["count"].(int64); ok {
				count = val
			}

			statusCounts = append(statusCounts, StatusCount{
				Status:      getStringValue(row, "status"),
				Description: getStringValue(row, "description"),
				SortOrder:   getIntValue(row, "sort_order"),
				Count:       count,
			})
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"statusCounts": statusCounts,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding scan status response: %v", err)
		}
	}
}

// buildScanStatusQuery constructs the SQL query for scan status counts
// Only counts images that have at least one running container
func buildScanStatusQuery(namespaces, vulnStatuses, packageTypes, osNames []string) string {
	query := `
SELECT
    status.status,
    status.description,
    status.sort_order,
    COUNT(DISTINCT images.id) as count
FROM images images
JOIN scan_status status ON images.status = status.status
JOIN containers instances ON images.id = instances.image_id`

	// Build WHERE conditions
	var conditions []string

	// Namespace filter
	if len(namespaces) > 0 {
		escaped := make([]string, len(namespaces))
		for i, ns := range namespaces {
			escaped[i] = "'" + strings.ReplaceAll(ns, "'", "''") + "'"
		}
		conditions = append(conditions, "instances.namespace IN ("+strings.Join(escaped, ",")+")")
	}

	// OS name filter
	if len(osNames) > 0 {
		escaped := make([]string, len(osNames))
		for i, os := range osNames {
			escaped[i] = "'" + strings.ReplaceAll(os, "'", "''") + "'"
		}
		conditions = append(conditions, "images.os_name IN ("+strings.Join(escaped, ",")+")")
	}

	// Note: vulnStatuses and packageTypes filters affect vulnerability/package subqueries
	// For scan status counts, we count images regardless of their vulnerability details
	// These filters would require complex subqueries, so we omit them for now

	// Add WHERE clause
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Group by and having
	query += `
GROUP BY status.status, status.description, status.sort_order
HAVING count > 0
ORDER BY status.sort_order`

	return query
}

// NamespaceSummaryHandler creates an HTTP handler for /api/summary/by-namespace endpoint
// Returns namespace-level vulnerability aggregations (averages per container)
func NamespaceSummaryHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters (multiselect - comma separated)
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildNamespaceSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing namespace count query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := int64(0)
		if len(countResult.Rows) > 0 {
			if count, ok := countResult.Rows[0]["COUNT(*)"].(int64); ok {
				totalCount = count
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error executing namespace summary query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse results
		namespaceData := make([]map[string]interface{}, 0, len(result.Rows))
		for _, row := range result.Rows {
			namespaceData = append(namespaceData, map[string]interface{}{
				"namespace":        getStringValue(row, "namespace"),
				"container_count":   getIntValue(row, "container_count"),
				"avg_critical":     roundToOne(getFloatValue(row, "avg_critical")),
				"avg_high":         roundToOne(getFloatValue(row, "avg_high")),
				"avg_medium":       roundToOne(getFloatValue(row, "avg_medium")),
				"avg_low":          roundToOne(getFloatValue(row, "avg_low")),
				"avg_negligible":   roundToOne(getFloatValue(row, "avg_negligible")),
				"avg_unknown":      roundToOne(getFloatValue(row, "avg_unknown")),
				"avg_risk":         roundToOne(getFloatValue(row, "avg_risk")),
				"avg_exploits":     roundToOne(getFloatValue(row, "avg_exploits")),
				"avg_packages":     roundToOne(getFloatValue(row, "avg_packages")),
			})
		}

		// Handle CSV export
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=namespace_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			if err := writer.Write([]string{
				"Namespace", "Containers", "Avg Critical", "Avg High", "Avg Medium",
				"Avg Low", "Avg Negligible", "Avg Unknown", "Avg Risk Score", "Avg Exploits", "Avg Packages",
			}); err != nil {
				log.Printf("Error writing CSV header: %v", err)
				http.Error(w, "Error generating CSV", http.StatusInternalServerError)
				return
			}

			// Write data
			for _, item := range namespaceData {
				if err := writer.Write([]string{
					fmt.Sprintf("%v", item["namespace"]),
					fmt.Sprintf("%v", item["container_count"]),
					fmt.Sprintf("%.1f", item["avg_critical"]),
					fmt.Sprintf("%.1f", item["avg_high"]),
					fmt.Sprintf("%.1f", item["avg_medium"]),
					fmt.Sprintf("%.1f", item["avg_low"]),
					fmt.Sprintf("%.1f", item["avg_negligible"]),
					fmt.Sprintf("%.1f", item["avg_unknown"]),
					fmt.Sprintf("%.1f", item["avg_risk"]),
					fmt.Sprintf("%.1f", item["avg_exploits"]),
					fmt.Sprintf("%.1f", item["avg_packages"]),
				}); err != nil {
					log.Printf("Error writing CSV row: %v", err)
					http.Error(w, "Error generating CSV", http.StatusInternalServerError)
					return
				}
			}
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"namespaces": namespaceData,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding namespace summary response: %v", err)
		}
	}
}

// buildNamespaceSummaryQuery constructs the SQL query for namespace-level aggregations
func buildNamespaceSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Build package type filter for packages subquery
	packageTypeFilter := ""
	if len(packageTypes) > 0 {
		escapedTypes := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escapedTypes[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		packageTypeFilter = "WHERE type IN (" + strings.Join(escapedTypes, ",") + ")"
	}

	// Build vulnerability filters for vulnerabilities subquery
	var vulnFilters []string
	if len(vulnStatuses) > 0 {
		escapedStatuses := make([]string, len(vulnStatuses))
		for i, status := range vulnStatuses {
			escapedStatuses[i] = "'" + strings.ReplaceAll(status, "'", "''") + "'"
		}
		vulnFilters = append(vulnFilters, "fix_status IN ("+strings.Join(escapedStatuses, ",")+")")
	}
	if len(packageTypes) > 0 {
		escapedTypes := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escapedTypes[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		vulnFilters = append(vulnFilters, "package_type IN ("+strings.Join(escapedTypes, ",")+")")
	}

	vulnStatusFilter := ""
	if len(vulnFilters) > 0 {
		vulnStatusFilter = "WHERE " + strings.Join(vulnFilters, " AND ")
	}

	// Base query with subqueries
	baseQuery := fmt.Sprintf(`
FROM containers instances
JOIN images images ON instances.image_id = images.id
JOIN scan_status status ON images.status = status.status
LEFT JOIN (
    SELECT image_id, COUNT(*) as package_count
    FROM packages
    %s
    GROUP BY image_id
) pkg_counts ON images.id = pkg_counts.image_id
LEFT JOIN (
    SELECT
        image_id,
        SUM(CASE WHEN LOWER(severity) = 'critical' THEN count ELSE 0 END) as critical_count,
        SUM(CASE WHEN LOWER(severity) = 'high' THEN count ELSE 0 END) as high_count,
        SUM(CASE WHEN LOWER(severity) = 'medium' THEN count ELSE 0 END) as medium_count,
        SUM(CASE WHEN LOWER(severity) = 'low' THEN count ELSE 0 END) as low_count,
        SUM(CASE WHEN LOWER(severity) = 'negligible' THEN count ELSE 0 END) as negligible_count,
        SUM(CASE WHEN LOWER(severity) = 'unknown' THEN count ELSE 0 END) as unknown_count,
        SUM(risk * count) as total_risk,
        SUM(known_exploited * count) as exploit_count
    FROM vulnerabilities
    %s
    GROUP BY image_id
) vuln_counts ON images.id = vuln_counts.image_id
WHERE status.status = 'completed'`, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Namespace filter
	if len(namespaces) > 0 {
		escaped := make([]string, len(namespaces))
		for i, ns := range namespaces {
			escaped[i] = "'" + strings.ReplaceAll(ns, "'", "''") + "'"
		}
		conditions = append(conditions, "instances.namespace IN ("+strings.Join(escaped, ",")+")")
	}

	// OS name filter
	if len(osNames) > 0 {
		escaped := make([]string, len(osNames))
		for i, os := range osNames {
			escaped[i] = "'" + strings.ReplaceAll(os, "'", "''") + "'"
		}
		conditions = append(conditions, "images.os_name IN ("+strings.Join(escaped, ",")+")")
	}

	// Add conditions to base query
	whereClause := baseQuery
	if len(conditions) > 0 {
		whereClause += " AND " + strings.Join(conditions, " AND ")
	}

	// Group by
	groupBy := " GROUP BY instances.namespace"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.namespace" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
    instances.namespace,
    COUNT(DISTINCT instances.id) as container_count,
    AVG(COALESCE(vuln_counts.critical_count, 0)) as avg_critical,
    AVG(COALESCE(vuln_counts.high_count, 0)) as avg_high,
    AVG(COALESCE(vuln_counts.medium_count, 0)) as avg_medium,
    AVG(COALESCE(vuln_counts.low_count, 0)) as avg_low,
    AVG(COALESCE(vuln_counts.negligible_count, 0)) as avg_negligible,
    AVG(COALESCE(vuln_counts.unknown_count, 0)) as avg_unknown,
    AVG(COALESCE(vuln_counts.total_risk, 0)) as avg_risk,
    AVG(COALESCE(vuln_counts.exploit_count, 0)) as avg_exploits,
    AVG(COALESCE(pkg_counts.package_count, 0)) as avg_packages`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting with namespace as secondary sort
	validSortColumns := map[string]bool{
		"namespace": true, "container_count": true, "avg_critical": true,
		"avg_high": true, "avg_medium": true, "avg_low": true,
		"avg_negligible": true, "avg_unknown": true, "avg_risk": true,
		"avg_exploits": true, "avg_packages": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
		// Add namespace as secondary sort (for tie-breaking), unless it's the primary sort
		if sortBy != "namespace" {
			mainQuery += ", namespace ASC"
		}
	} else {
		mainQuery += " ORDER BY namespace ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// DistributionSummaryHandler creates an HTTP handler for /api/summary/by-distribution endpoint
// Returns OS distribution-level vulnerability aggregations (averages per container)
func DistributionSummaryHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters (multiselect - comma separated)
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildDistributionSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing distribution count query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := int64(0)
		if len(countResult.Rows) > 0 {
			if count, ok := countResult.Rows[0]["COUNT(*)"].(int64); ok {
				totalCount = count
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error executing distribution summary query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse results
		distributionData := make([]map[string]interface{}, 0, len(result.Rows))
		for _, row := range result.Rows {
			distributionData = append(distributionData, map[string]interface{}{
				"os_name":          getStringValue(row, "os_name"),
				"container_count":   getIntValue(row, "container_count"),
				"avg_critical":     roundToOne(getFloatValue(row, "avg_critical")),
				"avg_high":         roundToOne(getFloatValue(row, "avg_high")),
				"avg_medium":       roundToOne(getFloatValue(row, "avg_medium")),
				"avg_low":          roundToOne(getFloatValue(row, "avg_low")),
				"avg_negligible":   roundToOne(getFloatValue(row, "avg_negligible")),
				"avg_unknown":      roundToOne(getFloatValue(row, "avg_unknown")),
				"avg_risk":         roundToOne(getFloatValue(row, "avg_risk")),
				"avg_exploits":     roundToOne(getFloatValue(row, "avg_exploits")),
				"avg_packages":     roundToOne(getFloatValue(row, "avg_packages")),
			})
		}

		// Handle CSV export
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=distribution_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			if err := writer.Write([]string{
				"OS Distribution", "Containers", "Avg Critical", "Avg High", "Avg Medium",
				"Avg Low", "Avg Negligible", "Avg Unknown", "Avg Risk Score", "Avg Exploits", "Avg Packages",
			}); err != nil {
				log.Printf("Error writing CSV header: %v", err)
				http.Error(w, "Error generating CSV", http.StatusInternalServerError)
				return
			}

			// Write data
			for _, item := range distributionData {
				if err := writer.Write([]string{
					fmt.Sprintf("%v", item["os_name"]),
					fmt.Sprintf("%v", item["container_count"]),
					fmt.Sprintf("%.1f", item["avg_critical"]),
					fmt.Sprintf("%.1f", item["avg_high"]),
					fmt.Sprintf("%.1f", item["avg_medium"]),
					fmt.Sprintf("%.1f", item["avg_low"]),
					fmt.Sprintf("%.1f", item["avg_negligible"]),
					fmt.Sprintf("%.1f", item["avg_unknown"]),
					fmt.Sprintf("%.1f", item["avg_risk"]),
					fmt.Sprintf("%.1f", item["avg_exploits"]),
					fmt.Sprintf("%.1f", item["avg_packages"]),
				}); err != nil {
					log.Printf("Error writing CSV row: %v", err)
					http.Error(w, "Error generating CSV", http.StatusInternalServerError)
					return
				}
			}
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"distributions": distributionData,
			"page":          page,
			"pageSize":      pageSize,
			"totalCount":    totalCount,
			"totalPages":    totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding distribution summary response: %v", err)
		}
	}
}

// buildDistributionSummaryQuery constructs the SQL query for distribution-level aggregations
func buildDistributionSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Build package type filter for packages subquery
	packageTypeFilter := ""
	if len(packageTypes) > 0 {
		escapedTypes := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escapedTypes[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		packageTypeFilter = "WHERE type IN (" + strings.Join(escapedTypes, ",") + ")"
	}

	// Build vulnerability filters for vulnerabilities subquery
	var vulnFilters []string
	if len(vulnStatuses) > 0 {
		escapedStatuses := make([]string, len(vulnStatuses))
		for i, status := range vulnStatuses {
			escapedStatuses[i] = "'" + strings.ReplaceAll(status, "'", "''") + "'"
		}
		vulnFilters = append(vulnFilters, "fix_status IN ("+strings.Join(escapedStatuses, ",")+")")
	}
	if len(packageTypes) > 0 {
		escapedTypes := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escapedTypes[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		vulnFilters = append(vulnFilters, "package_type IN ("+strings.Join(escapedTypes, ",")+")")
	}

	vulnStatusFilter := ""
	if len(vulnFilters) > 0 {
		vulnStatusFilter = "WHERE " + strings.Join(vulnFilters, " AND ")
	}

	// Base query with subqueries
	baseQuery := fmt.Sprintf(`
FROM containers instances
JOIN images images ON instances.image_id = images.id
JOIN scan_status status ON images.status = status.status
LEFT JOIN (
    SELECT image_id, COUNT(*) as package_count
    FROM packages
    %s
    GROUP BY image_id
) pkg_counts ON images.id = pkg_counts.image_id
LEFT JOIN (
    SELECT
        image_id,
        SUM(CASE WHEN LOWER(severity) = 'critical' THEN count ELSE 0 END) as critical_count,
        SUM(CASE WHEN LOWER(severity) = 'high' THEN count ELSE 0 END) as high_count,
        SUM(CASE WHEN LOWER(severity) = 'medium' THEN count ELSE 0 END) as medium_count,
        SUM(CASE WHEN LOWER(severity) = 'low' THEN count ELSE 0 END) as low_count,
        SUM(CASE WHEN LOWER(severity) = 'negligible' THEN count ELSE 0 END) as negligible_count,
        SUM(CASE WHEN LOWER(severity) = 'unknown' THEN count ELSE 0 END) as unknown_count,
        SUM(risk * count) as total_risk,
        SUM(known_exploited * count) as exploit_count
    FROM vulnerabilities
    %s
    GROUP BY image_id
) vuln_counts ON images.id = vuln_counts.image_id
WHERE status.status = 'completed'
  AND images.os_name IS NOT NULL
  AND images.os_name != ''`, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Namespace filter
	if len(namespaces) > 0 {
		escaped := make([]string, len(namespaces))
		for i, ns := range namespaces {
			escaped[i] = "'" + strings.ReplaceAll(ns, "'", "''") + "'"
		}
		conditions = append(conditions, "instances.namespace IN ("+strings.Join(escaped, ",")+")")
	}

	// OS name filter
	if len(osNames) > 0 {
		escaped := make([]string, len(osNames))
		for i, os := range osNames {
			escaped[i] = "'" + strings.ReplaceAll(os, "'", "''") + "'"
		}
		conditions = append(conditions, "images.os_name IN ("+strings.Join(escaped, ",")+")")
	}

	// Add conditions to base query
	whereClause := baseQuery
	if len(conditions) > 0 {
		whereClause += " AND " + strings.Join(conditions, " AND ")
	}

	// Group by
	groupBy := " GROUP BY images.os_name"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT images.os_name" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
    images.os_name,
    COUNT(DISTINCT instances.id) as container_count,
    AVG(COALESCE(vuln_counts.critical_count, 0)) as avg_critical,
    AVG(COALESCE(vuln_counts.high_count, 0)) as avg_high,
    AVG(COALESCE(vuln_counts.medium_count, 0)) as avg_medium,
    AVG(COALESCE(vuln_counts.low_count, 0)) as avg_low,
    AVG(COALESCE(vuln_counts.negligible_count, 0)) as avg_negligible,
    AVG(COALESCE(vuln_counts.unknown_count, 0)) as avg_unknown,
    AVG(COALESCE(vuln_counts.total_risk, 0)) as avg_risk,
    AVG(COALESCE(vuln_counts.exploit_count, 0)) as avg_exploits,
    AVG(COALESCE(pkg_counts.package_count, 0)) as avg_packages`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting with os_name as secondary sort
	validSortColumns := map[string]bool{
		"os_name": true, "container_count": true, "avg_critical": true,
		"avg_high": true, "avg_medium": true, "avg_low": true,
		"avg_negligible": true, "avg_unknown": true, "avg_risk": true,
		"avg_exploits": true, "avg_packages": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
		// Add os_name as secondary sort (for tie-breaking), unless it's the primary sort
		if sortBy != "os_name" {
			mainQuery += ", os_name ASC"
		}
	} else {
		mainQuery += " ORDER BY os_name ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// Helper functions

func getStringValue(row map[string]interface{}, key string) string {
	if val, ok := row[key].(string); ok {
		return val
	}
	return ""
}

func getIntValue(row map[string]interface{}, key string) int {
	if val, ok := row[key].(int64); ok {
		return int(val)
	}
	return 0
}

func getFloatValue(row map[string]interface{}, key string) float64 {
	if val, ok := row[key].(float64); ok {
		return val
	}
	if val, ok := row[key].(int64); ok {
		return float64(val)
	}
	return 0
}

func roundToOne(val float64) float64 {
	return math.Round(val*10) / 10
}
