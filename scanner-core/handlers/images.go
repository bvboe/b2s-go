package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// ImageQueryProvider defines the interface for executing image queries
type ImageQueryProvider interface {
	ExecuteReadOnlyQuery(query string) (*database.QueryResult, error)
}

// FilterOptionsHandler creates an HTTP handler for /api/filter-options endpoint
// Returns distinct values for all filter dropdowns
func FilterOptionsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		queries := map[string]string{
			"namespaces": "SELECT DISTINCT namespace FROM container_instances WHERE namespace IS NOT NULL AND namespace != '' ORDER BY namespace",
			"osNames":    "SELECT DISTINCT os_name FROM container_images WHERE os_name IS NOT NULL AND os_name != '' ORDER BY os_name",
			"vulnStatuses": "SELECT DISTINCT fix_status FROM vulnerabilities WHERE fix_status IS NOT NULL AND fix_status != '' ORDER BY fix_status",
			"packageTypes": "SELECT DISTINCT type FROM packages WHERE type IS NOT NULL AND type != '' ORDER BY type",
		}

		response := make(map[string][]string)

		for key, query := range queries {
			result, err := provider.ExecuteReadOnlyQuery(query)
			if err != nil {
				log.Printf("Error fetching %s: %v", key, err)
				continue
			}

			values := make([]string, 0, len(result.Rows))
			for _, row := range result.Rows {
				// Get the first column value
				for _, val := range row {
					if str, ok := val.(string); ok && str != "" {
						values = append(values, str)
					}
					break // Only take first column
				}
			}
			response[key] = values
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding filter options: %v", err)
		}
	}
}

// ImagesHandler creates an HTTP handler for /api/images endpoint
func ImagesHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Pagination
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// Search
		search := params.Get("search")

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

		// Export format
		format := params.Get("format")

		// Build query
		query, countQuery := buildImagesQuery(search, namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing count query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := 0
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = int(count)
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error executing images query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportCSV(w, result)
			return
		}

		// Rows are already maps, just use them directly
		response := map[string]interface{}{
			"images":     result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": (totalCount + pageSize - 1) / pageSize,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding JSON: %v", err)
		}
	}
}

// parseMultiSelect parses comma-separated values from query parameter
func parseMultiSelect(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// buildImagesQuery constructs the SQL query with filters
func buildImagesQuery(search string, namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Base query
	baseQuery := `
  FROM container_instances instances
  JOIN container_images images ON instances.image_id = images.id
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
          SUM(risk) as total_risk,
          SUM(known_exploited) as exploit_count
      FROM vulnerabilities
      %s
      GROUP BY image_id
  ) vuln_counts ON images.id = vuln_counts.image_id
  WHERE 1=1`

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
	// This subquery needs to apply BOTH fix_status and package_type filters
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

	baseQuery = fmt.Sprintf(baseQuery, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Search filter (image name)
	if search != "" {
		escapedSearch := strings.ReplaceAll(search, "'", "''")
		conditions = append(conditions, fmt.Sprintf("(instances.repository || ':' || instances.tag) LIKE '%%%s%%'", escapedSearch))
	}

	// Namespace filter
	if len(namespaces) > 0 {
		escaped := make([]string, len(namespaces))
		for i, ns := range namespaces {
			escaped[i] = "'" + strings.ReplaceAll(ns, "'", "''") + "'"
		}
		conditions = append(conditions, "instances.namespace IN ("+strings.Join(escaped, ",")+")")
	}

	// Note: Vulnerability fix status filter is now applied in the vulnerabilities subquery

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
	groupBy := " GROUP BY instances.repository || ':' || instances.tag, images.os_name, status.status"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.repository || ':' || instances.tag as image" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
      instances.repository || ':' || instances.tag as image,
      COUNT(*) as instance_count,
      COALESCE(vuln_counts.critical_count, 0) as critical_count,
      COALESCE(vuln_counts.high_count, 0) as high_count,
      COALESCE(vuln_counts.medium_count, 0) as medium_count,
      COALESCE(vuln_counts.low_count, 0) as low_count,
      COALESCE(vuln_counts.negligible_count, 0) as negligible_count,
      COALESCE(vuln_counts.unknown_count, 0) as unknown_count,
      COALESCE(vuln_counts.total_risk, 0) as total_risk,
      COALESCE(vuln_counts.exploit_count, 0) as exploit_count,
      COALESCE(pkg_counts.package_count, 0) as package_count,
      status.description as status_description,
      images.os_name`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting
	// IMPORTANT: Always sort by status.sort_order first to ensure completed scans appear at top
	validSortColumns := map[string]bool{
		"image": true, "instance_count": true, "critical_count": true,
		"high_count": true, "medium_count": true, "low_count": true,
		"negligible_count": true, "unknown_count": true, "total_risk": true,
		"exploit_count": true, "package_count": true, "os_name": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s", sortBy, sortOrder)
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, image ASC"
	}

	// Add pagination
	mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	return mainQuery, countQuery
}

// PodsHandler creates an HTTP handler for /api/pods endpoint
func PodsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Pagination
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// Search
		search := params.Get("search")

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

		// Export format
		format := params.Get("format")

		// Build query
		query, countQuery := buildPodsQuery(search, namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing count query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := 0
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = int(count)
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error executing pods query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportPodsCSV(w, result)
			return
		}

		// Rows are already maps, just use them directly
		response := map[string]interface{}{
			"pods":       result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": (totalCount + pageSize - 1) / pageSize,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding JSON: %v", err)
		}
	}
}

// buildPodsQuery constructs the SQL query for container instances with filters
func buildPodsQuery(search string, namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Base query - individual container instances
	baseQuery := `
  FROM container_instances instances
  JOIN container_images images ON instances.image_id = images.id
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
          SUM(risk) as total_risk,
          SUM(known_exploited) as exploit_count
      FROM vulnerabilities
      %s
      GROUP BY image_id
  ) vuln_counts ON images.id = vuln_counts.image_id
  WHERE 1=1`

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

	baseQuery = fmt.Sprintf(baseQuery, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Search filter (pod, container, or namespace)
	if search != "" {
		escapedSearch := strings.ReplaceAll(search, "'", "''")
		conditions = append(conditions, fmt.Sprintf("(instances.namespace LIKE '%%%s%%' OR instances.pod LIKE '%%%s%%' OR instances.container LIKE '%%%s%%')", escapedSearch, escapedSearch, escapedSearch))
	}

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

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.id" +
		whereClause +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
      instances.namespace,
      instances.pod,
      instances.container,
      COALESCE(vuln_counts.critical_count, 0) as critical_count,
      COALESCE(vuln_counts.high_count, 0) as high_count,
      COALESCE(vuln_counts.medium_count, 0) as medium_count,
      COALESCE(vuln_counts.low_count, 0) as low_count,
      COALESCE(vuln_counts.negligible_count, 0) as negligible_count,
      COALESCE(vuln_counts.unknown_count, 0) as unknown_count,
      COALESCE(vuln_counts.total_risk, 0) as total_risk,
      COALESCE(vuln_counts.exploit_count, 0) as exploit_count,
      COALESCE(pkg_counts.package_count, 0) as package_count,
      status.description as status_description,
      images.os_name`

	mainQuery := selectClause + whereClause

	// Add sorting
	// IMPORTANT: Always sort by status.sort_order first to ensure completed scans appear at top
	// Then sort by user's chosen column, then by namespace/pod/container for stable ordering
	validSortColumns := map[string]bool{
		"namespace": true, "pod": true, "container": true,
		"critical_count": true, "high_count": true, "medium_count": true,
		"low_count": true, "negligible_count": true, "unknown_count": true,
		"total_risk": true, "exploit_count": true, "package_count": true,
		"os_name": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s, instances.namespace ASC, instances.pod ASC, instances.container ASC", sortBy, sortOrder)
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, instances.namespace ASC, instances.pod ASC, instances.container ASC"
	}

	// Add pagination
	mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)

	return mainQuery, countQuery
}

// exportCSV exports query results as CSV
func exportCSV(w http.ResponseWriter, result *database.QueryResult) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=images.csv")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write headers
	if err := writer.Write(result.Columns); err != nil {
		log.Printf("Error writing CSV headers: %v", err)
		return
	}

	// Write rows
	for _, rowMap := range result.Rows {
		strRow := make([]string, len(result.Columns))
		for i, col := range result.Columns {
			strRow[i] = fmt.Sprintf("%v", rowMap[col])
		}
		if err := writer.Write(strRow); err != nil {
			log.Printf("Error writing CSV row: %v", err)
			return
		}
	}
}

// exportPodsCSV exports pods query results as CSV
func exportPodsCSV(w http.ResponseWriter, result *database.QueryResult) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=pods.csv")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write headers
	if err := writer.Write(result.Columns); err != nil {
		log.Printf("Error writing CSV headers: %v", err)
		return
	}

	// Write rows
	for _, rowMap := range result.Rows {
		strRow := make([]string, len(result.Columns))
		for i, col := range result.Columns {
			strRow[i] = fmt.Sprintf("%v", rowMap[col])
		}
		if err := writer.Write(strRow); err != nil {
			log.Printf("Error writing CSV row: %v", err)
			return
		}
	}
}
