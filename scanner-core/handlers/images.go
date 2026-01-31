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
			"namespaces":   "SELECT DISTINCT namespace FROM container_instances WHERE namespace IS NOT NULL AND namespace != '' ORDER BY namespace",
			"osNames":      "SELECT DISTINCT os_name FROM container_images WHERE os_name IS NOT NULL AND os_name != '' ORDER BY os_name",
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

		// Export format
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

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
          SUM(risk * count) as total_risk,
          SUM(known_exploited * count) as exploit_count
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
		conditions = append(conditions, fmt.Sprintf("instances.reference LIKE '%%%s%%'", escapedSearch))
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
	groupBy := " GROUP BY instances.reference, images.digest, images.os_name, status.status"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.reference as image" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
      instances.reference as image,
      images.digest,
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

	// Add sorting with multi-level hierarchy:
	// 1. status.sort_order (always first - groups by scan status priority)
	// 2. User-selected column (if any)
	// 3. image (always last - for consistent tie-breaking)
	validSortColumns := map[string]bool{
		"image": true, "instance_count": true, "critical_count": true,
		"high_count": true, "medium_count": true, "low_count": true,
		"negligible_count": true, "unknown_count": true, "total_risk": true,
		"exploit_count": true, "package_count": true, "os_name": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s", sortBy, sortOrder)
		// Add image as tertiary sort (for tie-breaking), unless it's the secondary sort
		if sortBy != "image" {
			mainQuery += ", image ASC"
		}
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, image ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// PodsHandler creates an HTTP handler for /api/pods endpoint
func PodsHandler(provider ImageQueryProvider) http.HandlerFunc {
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
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

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
          SUM(risk * count) as total_risk,
          SUM(known_exploited * count) as exploit_count
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
      images.digest,
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

	// Add sorting with multi-level hierarchy:
	// 1. status.sort_order (always first - groups by scan status priority)
	// 2. User-selected column (if any)
	// 3. namespace/pod/container (always last - for consistent tie-breaking, avoiding duplicates)
	validSortColumns := map[string]bool{
		"namespace": true, "pod": true, "container": true,
		"critical_count": true, "high_count": true, "medium_count": true,
		"low_count": true, "negligible_count": true, "unknown_count": true,
		"total_risk": true, "exploit_count": true, "package_count": true,
		"os_name": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s", sortBy, sortOrder)

		// Add namespace/pod/container as tie-breakers, skipping any already used
		if sortBy != "namespace" {
			mainQuery += ", instances.namespace ASC"
		}
		if sortBy != "pod" {
			mainQuery += ", instances.pod ASC"
		}
		if sortBy != "container" {
			mainQuery += ", instances.container ASC"
		}
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, instances.namespace ASC, instances.pod ASC, instances.container ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

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

// ImageDetailFullHandler creates an HTTP handler for /api/images/{digest} endpoint
// Returns detailed information for a specific image including repositories and instances
func ImageDetailFullHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		log.Printf("ImageDetailFullHandler: received path: %s", path)

		if len(path) <= 12 { // "/api/images/" is 12 characters
			log.Printf("ImageDetailFullHandler: path too short: %d chars", len(path))
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[12:] // Remove "/api/images/" prefix
		log.Printf("ImageDetailFullHandler: extracted digest: %s", digest)

		if digest == "" {
			log.Printf("ImageDetailFullHandler: empty digest")
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Build query to get basic image details
		escapedDigest := strings.ReplaceAll(digest, "'", "''")
		imageQuery := `
SELECT
    images.id,
    images.digest as image_id,
    images.status as scan_status,
    images.os_name as distro_display_name,
    status.description as status_description,
    images.vulns_scanned_at,
    images.grype_db_built
FROM container_images images
JOIN scan_status status ON images.status = status.status
WHERE images.digest = '` + escapedDigest + `'`

		log.Printf("ImageDetailFullHandler: executing image query for digest: %s", digest)
		imageResult, err := provider.ExecuteReadOnlyQuery(imageQuery)
		if err != nil {
			log.Printf("Error querying image details for %s: %v", digest, err)
			http.Error(w, fmt.Sprintf("Error querying image: %v", err), http.StatusInternalServerError)
			return
		}

		if len(imageResult.Rows) == 0 {
			log.Printf("No image found with digest: %s", digest)
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}

		log.Printf("ImageDetailFullHandler: found image")
		imageRow := imageResult.Rows[0]
		imageID := imageRow["id"]

		// Get distinct repositories for this image
		repoQuery := `
SELECT DISTINCT reference as repo
FROM container_instances
WHERE image_id = ` + fmt.Sprintf("%v", imageID) + `
ORDER BY reference`

		log.Printf("ImageDetailFullHandler: fetching repositories for image_id: %v", imageID)
		repoResult, err := provider.ExecuteReadOnlyQuery(repoQuery)
		if err != nil {
			log.Printf("Error querying repositories for image_id %v: %v", imageID, err)
			http.Error(w, fmt.Sprintf("Error querying repositories: %v", err), http.StatusInternalServerError)
			return
		}

		repositories := []string{}
		for _, row := range repoResult.Rows {
			if repo, ok := row["repo"].(string); ok && repo != "" {
				repositories = append(repositories, repo)
			}
		}
		log.Printf("ImageDetailFullHandler: found %d repositories", len(repositories))

		// Get distinct instances for this image
		instanceQuery := `
SELECT DISTINCT namespace || '.' || pod || '.' || container as instance
FROM container_instances
WHERE image_id = ` + fmt.Sprintf("%v", imageID) + `
ORDER BY namespace, pod, container`

		log.Printf("ImageDetailFullHandler: fetching instances for image_id: %v", imageID)
		instanceResult, err := provider.ExecuteReadOnlyQuery(instanceQuery)
		if err != nil {
			log.Printf("Error querying instances for image_id %v: %v", imageID, err)
			http.Error(w, fmt.Sprintf("Error querying instances: %v", err), http.StatusInternalServerError)
			return
		}

		instances := []string{}
		for _, row := range instanceResult.Rows {
			if inst, ok := row["instance"].(string); ok && inst != "" {
				instances = append(instances, inst)
			}
		}
		log.Printf("ImageDetailFullHandler: found %d instances", len(instances))

		response := map[string]interface{}{
			"image_id":            imageRow["image_id"],
			"repositories":        repositories,
			"instances":           instances,
			"distro_display_name": imageRow["distro_display_name"],
			"scan_status":         imageRow["scan_status"],
			"status_description":  imageRow["status_description"],
			"vulns_scanned_at":    imageRow["vulns_scanned_at"],
			"grype_db_built":      imageRow["grype_db_built"],
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding image detail response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// ImageVulnerabilitiesDetailHandler creates an HTTP handler for /api/images/{digest}/vulnerabilities endpoint
// Returns vulnerabilities for a specific image with filtering, sorting, and pagination
func ImageVulnerabilitiesDetailHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 16 || pathWithoutPrefix[len(pathWithoutPrefix)-16:] != "/vulnerabilities" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-16]

		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Handle raw JSON export from Grype
		if format == "json" {
			exportRawVulnerabilitiesJSON(w, provider, digest)
			return
		}

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

		// Filters
		severities := parseMultiSelect(params.Get("severity"))
		fixStatuses := parseMultiSelect(params.Get("fixStatus"))
		packageTypes := parseMultiSelect(params.Get("packageType"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildImageVulnerabilitiesQuery(digest, severities, fixStatuses, packageTypes, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing vulnerability count query: %v", err)
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
			log.Printf("Error executing vulnerability query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportVulnerabilitiesCSV(w, result)
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"vulnerabilities": result.Rows,
			"page":            page,
			"pageSize":        pageSize,
			"totalCount":      totalCount,
			"totalPages":      totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding vulnerabilities response: %v", err)
		}
	}
}

// buildImageVulnerabilitiesQuery constructs the SQL query for image vulnerabilities
func buildImageVulnerabilitiesQuery(digest string, severities, fixStatuses, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	escapedDigest := strings.ReplaceAll(digest, "'", "''")

	// Build WHERE conditions
	var conditions []string

	// Severity filter
	if len(severities) > 0 {
		escaped := make([]string, len(severities))
		for i, s := range severities {
			escaped[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
		}
		conditions = append(conditions, "v.severity IN ("+strings.Join(escaped, ",")+")")
	}

	// Fix status filter
	if len(fixStatuses) > 0 {
		escaped := make([]string, len(fixStatuses))
		for i, s := range fixStatuses {
			escaped[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
		}
		conditions = append(conditions, "v.fix_status IN ("+strings.Join(escaped, ",")+")")
	}

	// Package type filter
	if len(packageTypes) > 0 {
		escaped := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escaped[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		conditions = append(conditions, "v.package_type IN ("+strings.Join(escaped, ",")+")")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " AND " + strings.Join(conditions, " AND ")
	}

	// Base query
	baseQuery := fmt.Sprintf(`
FROM vulnerabilities v
JOIN container_images images ON v.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, whereClause)

	// Build count query
	countQuery := "SELECT COUNT(*)" + baseQuery

	// Build main query with sorting
	selectClause := `SELECT
    v.id,
    v.cve_id as vulnerability_id,
    v.package_name as artifact_name,
    v.package_version as artifact_version,
    v.fixed_version as vulnerability_fix_versions,
    v.fix_status as vulnerability_fix_state,
    v.package_type as artifact_type,
    v.severity as vulnerability_severity,
    v.risk as vulnerability_risk,
    v.known_exploited as vulnerability_known_exploits,
    v.count as vulnerability_count`

	mainQuery := selectClause + baseQuery

	// Add sorting
	validSortColumns := map[string]bool{
		"vulnerability_severity": true, "vulnerability_id": true, "artifact_name": true,
		"artifact_version": true, "vulnerability_fix_versions": true, "vulnerability_fix_state": true,
		"artifact_type": true, "vulnerability_risk": true, "vulnerability_known_exploits": true,
		"vulnerability_count": true,
	}

	// Build multi-level sort:
	// 1. User-selected column (if any, and not severity/vulnerability)
	// 2. Severity (always, using CASE for proper priority)
	// 3. Vulnerability ID (always, for consistent tie-breaking)

	mainQuery += "\nORDER BY\n"

	severityCase := `    CASE v.severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Negligible' THEN 5
        ELSE 6
    END`

	if sortBy != "" && validSortColumns[sortBy] {
		// Map UI column names to database columns
		dbColumn := sortBy
		switch sortBy {
		case "vulnerability_severity":
			// User clicked severity - it becomes primary, vulnerability becomes secondary
			mainQuery += severityCase + " " + sortOrder + ",\n"
			mainQuery += "    v.cve_id ASC"
			if limit > 0 {
				mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
			}
			return mainQuery, countQuery
		case "vulnerability_id":
			// User clicked vulnerability - it becomes primary, severity becomes secondary
			mainQuery += "    v.cve_id " + sortOrder + ",\n"
			mainQuery += severityCase + " ASC"
			if limit > 0 {
				mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
			}
			return mainQuery, countQuery
		case "artifact_name":
			dbColumn = "v.package_name"
		case "artifact_version":
			dbColumn = "v.package_version"
		case "vulnerability_fix_versions":
			dbColumn = "v.fixed_version"
		case "vulnerability_fix_state":
			dbColumn = "v.fix_status"
		case "artifact_type":
			dbColumn = "v.package_type"
		case "vulnerability_risk":
			dbColumn = "v.risk"
		case "vulnerability_known_exploits":
			dbColumn = "v.known_exploited"
		case "vulnerability_count":
			dbColumn = "v.count"
		}

		// User clicked a column: [column], severity, vulnerability
		mainQuery += fmt.Sprintf("    %s %s,\n", dbColumn, sortOrder)
		mainQuery += severityCase + " ASC,\n"
		mainQuery += "    v.cve_id ASC"
	} else {
		// Default: severity, vulnerability
		mainQuery += severityCase + " ASC,\n"
		mainQuery += "    v.cve_id ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// exportVulnerabilitiesCSV exports vulnerabilities as CSV
func exportVulnerabilitiesCSV(w http.ResponseWriter, result *database.QueryResult) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=vulnerabilities.csv")

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

// exportRawVulnerabilitiesJSON exports the raw Grype vulnerability JSON for an image
func exportRawVulnerabilitiesJSON(w http.ResponseWriter, provider ImageQueryProvider, digest string) {
	escapedDigest := strings.ReplaceAll(digest, "'", "''")
	query := `SELECT vulnerabilities FROM container_images WHERE digest = '` + escapedDigest + `'`

	result, err := provider.ExecuteReadOnlyQuery(query)
	if err != nil || len(result.Rows) == 0 {
		log.Printf("Error fetching raw vulnerabilities JSON: %v", err)
		http.Error(w, "Vulnerabilities JSON not found", http.StatusNotFound)
		return
	}

	vulnJSON, ok := result.Rows[0]["vulnerabilities"].(string)
	if !ok || vulnJSON == "" {
		http.Error(w, "No vulnerabilities data available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=grype-vulnerabilities.json")
	if _, err := w.Write([]byte(vulnJSON)); err != nil {
		log.Printf("Error writing vulnerabilities JSON: %v", err)
	}
}

// ImagePackagesDetailHandler creates an HTTP handler for /api/images/{digest}/packages endpoint
// Returns packages for a specific image with filtering, sorting, and pagination
func ImagePackagesDetailHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 9 || pathWithoutPrefix[len(pathWithoutPrefix)-9:] != "/packages" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-9]

		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Handle raw JSON export from Syft
		if format == "json" {
			exportRawSBOMJSON(w, provider, digest)
			return
		}

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

		// Filters
		packageTypes := parseMultiSelect(params.Get("type"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildImagePackagesQuery(digest, packageTypes, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Printf("Error executing package count query: %v", err)
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
			log.Printf("Error executing package query: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportPackagesCSV(w, result)
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"packages":   result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding packages response: %v", err)
		}
	}
}

// buildImagePackagesQuery constructs the SQL query for image packages
func buildImagePackagesQuery(digest string, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	escapedDigest := strings.ReplaceAll(digest, "'", "''")

	// Build WHERE conditions
	var conditions []string

	// Package type filter
	if len(packageTypes) > 0 {
		escaped := make([]string, len(packageTypes))
		for i, t := range packageTypes {
			escaped[i] = "'" + strings.ReplaceAll(t, "'", "''") + "'"
		}
		conditions = append(conditions, "p.type IN ("+strings.Join(escaped, ",")+")")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " AND " + strings.Join(conditions, " AND ")
	}

	// Base query
	baseQuery := fmt.Sprintf(`
FROM packages p
JOIN container_images images ON p.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, whereClause)

	// Build count query
	countQuery := "SELECT COUNT(*)" + baseQuery

	// Build main query with sorting
	selectClause := `SELECT
    p.id,
    p.name,
    p.version,
    p.type,
    p.number_of_instances as count`

	mainQuery := selectClause + baseQuery

	// Add sorting with multi-level sort:
	// Default: name, version, type
	// User clicks column: that column, name, version, type (avoiding duplicates)
	validSortColumns := map[string]bool{
		"name": true, "version": true, "type": true, "count": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		dbColumn := "p." + sortBy
		if sortBy == "count" {
			dbColumn = "p.number_of_instances"
		}
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", dbColumn, sortOrder)

		// Add tie-breakers (avoiding duplicates)
		if sortBy != "name" {
			mainQuery += ", p.name ASC"
		}
		if sortBy != "version" {
			mainQuery += ", p.version ASC"
		}
		if sortBy != "type" {
			mainQuery += ", p.type ASC"
		}
	} else {
		mainQuery += " ORDER BY p.name ASC, p.version ASC, p.type ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// exportPackagesCSV exports packages as CSV
func exportPackagesCSV(w http.ResponseWriter, result *database.QueryResult) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=packages.csv")

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

// exportRawSBOMJSON exports the raw Syft SBOM JSON for an image
func exportRawSBOMJSON(w http.ResponseWriter, provider ImageQueryProvider, digest string) {
	escapedDigest := strings.ReplaceAll(digest, "'", "''")
	query := `SELECT sbom FROM container_images WHERE digest = '` + escapedDigest + `'`

	result, err := provider.ExecuteReadOnlyQuery(query)
	if err != nil || len(result.Rows) == 0 {
		log.Printf("Error fetching raw SBOM JSON: %v", err)
		http.Error(w, "SBOM JSON not found", http.StatusNotFound)
		return
	}

	sbomJSON, ok := result.Rows[0]["sbom"].(string)
	if !ok || sbomJSON == "" {
		http.Error(w, "No SBOM data available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=syft-sbom.json")
	if _, err := w.Write([]byte(sbomJSON)); err != nil {
		log.Printf("Error writing SBOM JSON: %v", err)
	}
}

// VulnerabilityDetailsHandler returns the full JSON details for a specific vulnerability
func VulnerabilityDetailsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract vulnerability ID from URL path
		// Expected format: /api/vulnerabilities/{id}/details
		path := r.URL.Path
		log.Printf("VulnerabilityDetailsHandler - full path: %s", path)

		// Remove "/api/vulnerabilities/" prefix (21 characters) and "/details" suffix (8 characters)
		// Minimum valid path is 29 chars (with 1-digit ID), so check for < 29
		if len(path) < 29 {
			log.Printf("VulnerabilityDetailsHandler - path too short: %d characters", len(path))
			http.Error(w, "Invalid vulnerability ID", http.StatusBadRequest)
			return
		}

		vulnIDStr := path[21 : len(path)-8] // Extract ID from path (21 = length of "/api/vulnerabilities/")
		log.Printf("VulnerabilityDetailsHandler - extracted ID string: '%s'", vulnIDStr)

		// Validate that the ID is a valid integer
		vulnID, err := strconv.ParseInt(vulnIDStr, 10, 64)
		if err != nil {
			log.Printf("VulnerabilityDetailsHandler - invalid ID format: %s, error: %v", vulnIDStr, err)
			http.Error(w, "Invalid vulnerability ID format", http.StatusBadRequest)
			return
		}

		log.Printf("Fetching details for vulnerability ID: %d", vulnID)

		// Query vulnerability_details table
		query := fmt.Sprintf(`
			SELECT vd.details
			FROM vulnerability_details vd
			WHERE vd.vulnerability_id = %d`, vulnID)

		log.Printf("VulnerabilityDetailsHandler - executing query: %s", query)

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error fetching vulnerability details: %v", err)
			http.Error(w, "Failed to fetch vulnerability details", http.StatusInternalServerError)
			return
		}

		log.Printf("VulnerabilityDetailsHandler - query returned %d rows", len(result.Rows))

		if len(result.Rows) == 0 {
			log.Printf("VulnerabilityDetailsHandler - no details found for ID %d", vulnID)
			http.Error(w, "Vulnerability details not found", http.StatusNotFound)
			return
		}

		detailsJSON, ok := result.Rows[0]["details"].(string)
		if !ok || detailsJSON == "" {
			log.Printf("VulnerabilityDetailsHandler - details field is empty or wrong type")
			http.Error(w, "No details available", http.StatusNotFound)
			return
		}

		log.Printf("VulnerabilityDetailsHandler - returning %d bytes of JSON", len(detailsJSON))
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(detailsJSON)); err != nil {
			log.Printf("Error writing vulnerability details: %v", err)
		}
	}
}

// PackageDetailsHandler returns the full JSON details for a specific package
func PackageDetailsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract package ID from URL path
		// Expected format: /api/packages/{id}/details
		path := r.URL.Path
		log.Printf("PackageDetailsHandler - full path: %s", path)

		// Remove "/api/packages/" prefix (14 characters) and "/details" suffix (8 characters)
		// Minimum valid path is 22 chars (with 1-digit ID), so check for < 22
		if len(path) < 22 {
			log.Printf("PackageDetailsHandler - path too short: %d characters", len(path))
			http.Error(w, "Invalid package ID", http.StatusBadRequest)
			return
		}

		pkgIDStr := path[14 : len(path)-8] // Extract ID from path
		log.Printf("PackageDetailsHandler - extracted ID string: '%s'", pkgIDStr)

		// Validate that the ID is a valid integer
		pkgID, err := strconv.ParseInt(pkgIDStr, 10, 64)
		if err != nil {
			log.Printf("PackageDetailsHandler - invalid ID format: %s, error: %v", pkgIDStr, err)
			http.Error(w, "Invalid package ID format", http.StatusBadRequest)
			return
		}

		log.Printf("Fetching details for package ID: %d", pkgID)

		// Query package_details table
		query := fmt.Sprintf(`
			SELECT pd.details
			FROM package_details pd
			WHERE pd.package_id = %d`, pkgID)

		log.Printf("PackageDetailsHandler - executing query: %s", query)

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Printf("Error fetching package details: %v", err)
			http.Error(w, "Failed to fetch package details", http.StatusInternalServerError)
			return
		}

		log.Printf("PackageDetailsHandler - query returned %d rows", len(result.Rows))

		if len(result.Rows) == 0 {
			log.Printf("PackageDetailsHandler - no details found for ID %d", pkgID)
			http.Error(w, "Package details not found", http.StatusNotFound)
			return
		}

		detailsJSON, ok := result.Rows[0]["details"].(string)
		if !ok || detailsJSON == "" {
			log.Printf("PackageDetailsHandler - details field is empty or wrong type")
			http.Error(w, "No details available", http.StatusNotFound)
			return
		}

		log.Printf("PackageDetailsHandler - returning %d bytes of JSON", len(detailsJSON))
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(detailsJSON)); err != nil {
			log.Printf("Error writing package details: %v", err)
		}
	}
}
