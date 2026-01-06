package database

import (
	"database/sql"
	"fmt"
	"log"
)

// Package represents a package from the packages table
type Package struct {
	ID                int    `json:"id"`
	ImageID           int64  `json:"image_id"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	Type              string `json:"type"`
	NumberOfInstances int    `json:"number_of_instances"`
	CreatedAt         string `json:"created_at"`
}

// Vulnerability represents a vulnerability from the vulnerabilities table
type Vulnerability struct {
	ID             int     `json:"id"`
	ImageID        int64   `json:"image_id"`
	CVEID          string  `json:"cve_id"`
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	PackageType    string  `json:"package_type"`
	Severity       string  `json:"severity"`
	FixStatus      string  `json:"fix_status"`
	FixedVersion   string  `json:"fixed_version"`
	Count          int     `json:"count"`
	CreatedAt      string  `json:"created_at"`
}

// ImageSummary represents the summary information for an image
// Deprecated: This struct is kept for backward compatibility but image_summary table no longer exists
type ImageSummary struct {
	ImageID      int64  `json:"image_id"`
	PackageCount int    `json:"package_count"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	UpdatedAt    string `json:"updated_at"`
}

// ImageDetails combines image metadata with summary statistics
type ImageDetails struct {
	ID        int64  `json:"id"`
	Digest    string `json:"digest"`
	Status    string `json:"status"` // Unified status field
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// Deprecated: Use Status instead
	ScanStatus          string `json:"scan_status,omitempty"`
	VulnerabilityStatus string `json:"vulnerability_status,omitempty"`
	ScannedAt           string `json:"scanned_at,omitempty"`

	// Summary data
	PackageCount       int    `json:"package_count"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	CriticalCount      int    `json:"critical_count"`
	HighCount          int    `json:"high_count"`
	MediumCount        int    `json:"medium_count"`
	LowCount           int    `json:"low_count"`
	OSName             string `json:"os_name,omitempty"`
	OSVersion          string `json:"os_version,omitempty"`
}

// GetPackagesByImage returns all packages for a specific image
func (db *DB) GetPackagesByImage(digest string) (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT p.id, p.image_id, p.name, p.version, p.type, p.number_of_instances, p.created_at
		FROM packages p
		JOIN container_images img ON p.image_id = img.id
		WHERE img.digest = ?
		ORDER BY p.name, p.version
	`, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to query packages: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Warning: Failed to close rows: %v", err)
		}
	}()

	var packages []Package
	for rows.Next() {
		var pkg Package
		err := rows.Scan(&pkg.ID, &pkg.ImageID, &pkg.Name, &pkg.Version, &pkg.Type,
			&pkg.NumberOfInstances, &pkg.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetVulnerabilitiesByImage returns all vulnerabilities for a specific image
func (db *DB) GetVulnerabilitiesByImage(digest string) (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT v.id, v.image_id, v.cve_id, v.package_name, v.package_version, v.package_type,
		       v.severity, v.fix_status, v.fixed_version, v.count, v.created_at
		FROM vulnerabilities v
		JOIN container_images img ON v.image_id = img.id
		WHERE img.digest = ?
		ORDER BY
			CASE v.severity
				WHEN 'Critical' THEN 1
				WHEN 'High' THEN 2
				WHEN 'Medium' THEN 3
				WHEN 'Low' THEN 4
				WHEN 'Negligible' THEN 5
				ELSE 6
			END,
			v.cve_id
	`, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Warning: Failed to close rows: %v", err)
		}
	}()

	var vulns []Vulnerability
	for rows.Next() {
		var vuln Vulnerability
		err := rows.Scan(&vuln.ID, &vuln.ImageID, &vuln.CVEID, &vuln.PackageName,
			&vuln.PackageVersion, &vuln.PackageType, &vuln.Severity, &vuln.FixStatus,
			&vuln.FixedVersion, &vuln.Count, &vuln.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// GetImageSummary returns summary information for a specific image
// Package count is calculated dynamically from the packages table
func (db *DB) GetImageSummary(digest string) (interface{}, error) {
	var summary ImageSummary
	err := db.conn.QueryRow(`
		SELECT
			img.id,
			(SELECT COUNT(*) FROM packages WHERE image_id = img.id) as package_count,
			img.os_name,
			img.os_version,
			img.updated_at
		FROM container_images img
		WHERE img.digest = ?
	`, digest).Scan(&summary.ImageID, &summary.PackageCount, &summary.OSName,
		&summary.OSVersion, &summary.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil // No image found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image summary: %w", err)
	}

	return &summary, nil
}

// GetImageDetails returns detailed information including vulnerability counts
func (db *DB) GetImageDetails(digest string) (interface{}, error) {
	log.Printf("DEBUG GetImageDetails: digest=%q len=%d", digest, len(digest))
	var details ImageDetails
	var scannedAt sql.NullString
	var osName, osVersion sql.NullString

	// Get basic image info and calculate package count dynamically
	err := db.conn.QueryRow(`
		SELECT
			img.id, img.digest, img.status,
			img.created_at, img.updated_at, img.sbom_scanned_at,
			(SELECT COUNT(*) FROM packages WHERE image_id = img.id),
			COALESCE(img.os_name, ''),
			COALESCE(img.os_version, '')
		FROM container_images img
		WHERE img.digest = ?
	`, digest).Scan(&details.ID, &details.Digest, &details.Status,
		&details.CreatedAt, &details.UpdatedAt, &scannedAt, &details.PackageCount,
		&osName, &osVersion)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image details: %w", err)
	}

	if scannedAt.Valid {
		details.ScannedAt = scannedAt.String
	}
	if osName.Valid {
		details.OSName = osName.String
	}
	if osVersion.Valid {
		details.OSVersion = osVersion.String
	}

	// Get vulnerability counts by severity
	rows, err := db.conn.Query(`
		SELECT
			LOWER(severity),
			SUM(count) as total
		FROM vulnerabilities
		WHERE image_id = ?
		GROUP BY LOWER(severity)
	`, details.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability counts: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Warning: Failed to close rows: %v", err)
		}
	}()

	totalVulns := 0
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability count: %w", err)
		}

		totalVulns += count
		switch severity {
		case "critical":
			details.CriticalCount = count
		case "high":
			details.HighCount = count
		case "medium":
			details.MediumCount = count
		case "low", "negligible":
			details.LowCount += count
		}
	}

	details.VulnerabilityCount = totalVulns

	return &details, nil
}

// GetAllImageDetails returns detailed information for all images
func (db *DB) GetAllImageDetails() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT
			img.id, img.digest, img.status,
			img.created_at, img.updated_at, img.sbom_scanned_at,
			(SELECT COUNT(*) FROM packages WHERE image_id = img.id),
			COALESCE(img.os_name, ''),
			COALESCE(img.os_version, '')
		FROM container_images img
		ORDER BY img.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}

	// Read all images first to avoid deadlock
	var images []ImageDetails
	for rows.Next() {
		var details ImageDetails
		var scannedAt sql.NullString
		var osName, osVersion sql.NullString

		err := rows.Scan(&details.ID, &details.Digest, &details.Status,
			&details.CreatedAt, &details.UpdatedAt, &scannedAt, &details.PackageCount,
			&osName, &osVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}

		if scannedAt.Valid {
			details.ScannedAt = scannedAt.String
		}
		if osName.Valid {
			details.OSName = osName.String
		}
		if osVersion.Valid {
			details.OSVersion = osVersion.String
		}

		images = append(images, details)
	}
	if err := rows.Close(); err != nil {
		log.Printf("Warning: Failed to close rows: %v", err)
	}

	// Now get vulnerability counts for each image
	for i := range images {
		vulnRows, err := db.conn.Query(`
			SELECT
				LOWER(severity),
				SUM(count) as total
			FROM vulnerabilities
			WHERE image_id = ?
			GROUP BY LOWER(severity)
		`, images[i].ID)
		if err == nil {
			totalVulns := 0
			for vulnRows.Next() {
				var severity string
				var count int
				if err := vulnRows.Scan(&severity, &count); err == nil {
					totalVulns += count
					switch severity {
					case "critical":
						images[i].CriticalCount = count
					case "high":
						images[i].HighCount = count
					case "medium":
						images[i].MediumCount = count
					case "low", "negligible":
						images[i].LowCount += count
					}
				}
			}
			images[i].VulnerabilityCount = totalVulns
			if err := vulnRows.Close(); err != nil {
				log.Printf("Warning: Failed to close vulnerability rows: %v", err)
			}
		}
	}

	return images, nil
}

// GetLastUpdatedTimestamp returns a change signature that detects any data modifications
// dataType parameter can be "image", "all", or empty (defaults to "all")
// Returns a signature in format: "timestamp|count" (e.g., "2025-12-24T18:00:00Z|42")
//
// This signature changes when:
// - container_images.updated_at changes (scans complete, data updated)
// - container_instances count changes (pods added/deleted)
//
// Using row count is necessary to detect deletions, since deleted rows have no
// timestamp to update.
func (db *DB) GetLastUpdatedTimestamp(dataType string) (string, error) {
	var signature sql.NullString

	// Build a signature combining timestamp and row count
	// This detects both data updates (timestamp) and structural changes (count)
	// Returns empty string if no images exist yet
	query := `
		SELECT
			CASE
				WHEN COUNT(*) = 0 THEN NULL
				ELSE MAX(updated_at) || '|' || (SELECT COUNT(*) FROM container_instances)
			END
		FROM container_images
	`

	err := db.conn.QueryRow(query).Scan(&signature)
	if err != nil {
		return "", fmt.Errorf("failed to get last updated signature: %w", err)
	}

	if !signature.Valid {
		return "", nil
	}

	return signature.String, nil
}

// ScannedContainerInstance represents a container instance for metrics
type ScannedContainerInstance struct {
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	NodeName   string `json:"node_name"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	OSName     string `json:"os_name"`
}

// GetScannedContainerInstances returns all container instances where scan is completed
func (db *DB) GetScannedContainerInstances() ([]ScannedContainerInstance, error) {
	rows, err := db.conn.Query(`
		SELECT
			ci.namespace,
			ci.pod,
			ci.container,
			ci.node_name,
			ci.repository,
			ci.tag,
			img.digest,
			COALESCE(img.os_name, '') as os_name
		FROM container_instances ci
		JOIN container_images img ON ci.image_id = img.id
		WHERE img.status = 'completed'
		ORDER BY ci.namespace, ci.pod, ci.container
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query scanned container instances: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Warning: Failed to close rows: %v", err)
		}
	}()

	var instances []ScannedContainerInstance
	for rows.Next() {
		var instance ScannedContainerInstance
		err := rows.Scan(
			&instance.Namespace,
			&instance.Pod,
			&instance.Container,
			&instance.NodeName,
			&instance.Repository,
			&instance.Tag,
			&instance.Digest,
			&instance.OSName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan container instance row: %w", err)
		}
		instances = append(instances, instance)
	}

	return instances, nil
}

// ImageScanStatusCount represents the count of images by scan status
type ImageScanStatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// GetImageScanStatusCounts returns the count of running images grouped by scan status
// Only counts images that have at least one running container instance
func (db *DB) GetImageScanStatusCounts() ([]ImageScanStatusCount, error) {
	// Get all possible statuses from scan_status table
	statusRows, err := db.conn.Query(`
		SELECT status FROM scan_status ORDER BY sort_order
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan statuses: %w", err)
	}

	var allStatuses []string
	for statusRows.Next() {
		var status string
		if err := statusRows.Scan(&status); err != nil {
			_ = statusRows.Close()
			return nil, fmt.Errorf("failed to scan status row: %w", err)
		}
		allStatuses = append(allStatuses, status)
	}
	if err := statusRows.Close(); err != nil {
		log.Printf("Warning: Failed to close status rows: %v", err)
	}

	// Get counts for running images (images with at least one container instance)
	rows, err := db.conn.Query(`
		SELECT
			img.status,
			COUNT(DISTINCT img.id) as count
		FROM container_images img
		INNER JOIN container_instances ci ON ci.image_id = img.id
		GROUP BY img.status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query image scan status counts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Build a map of status -> count
	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count row: %w", err)
		}
		statusCounts[status] = count
	}

	// Build result with all statuses (including zeros)
	result := make([]ImageScanStatusCount, 0, len(allStatuses))
	for _, status := range allStatuses {
		result = append(result, ImageScanStatusCount{
			Status: status,
			Count:  statusCounts[status], // defaults to 0 if not in map
		})
	}

	return result, nil
}

// VulnerabilityInstance represents a vulnerability found in a running container instance
type VulnerabilityInstance struct {
	VulnID         int64  `json:"vuln_id"`
	Namespace      string `json:"namespace"`
	Pod            string `json:"pod"`
	Container      string `json:"container"`
	NodeName       string `json:"node_name"`
	Repository     string `json:"repository"`
	Tag            string `json:"tag"`
	Digest         string `json:"digest"`
	OSName         string `json:"os_name"`
	CVEID          string `json:"cve_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	Severity       string `json:"severity"`
	FixStatus      string `json:"fix_status"`
	FixedVersion   string `json:"fixed_version"`
	Count          int     `json:"count"`
	KnownExploited int     `json:"known_exploited"`
	Risk           float64 `json:"risk"`
}

// GetVulnerabilityInstances returns all vulnerabilities for all running container instances
func (db *DB) GetVulnerabilityInstances() ([]VulnerabilityInstance, error) {
	rows, err := db.conn.Query(`
		SELECT
			v.id,
			ci.namespace,
			ci.pod,
			ci.container,
			ci.node_name,
			ci.repository,
			ci.tag,
			img.digest,
			COALESCE(img.os_name, '') as os_name,
			v.cve_id,
			COALESCE(v.package_name, '') as package_name,
			COALESCE(v.package_version, '') as package_version,
			COALESCE(v.severity, '') as severity,
			COALESCE(v.fix_status, '') as fix_status,
			COALESCE(v.fixed_version, '') as fixed_version,
			v.count,
			v.known_exploited,
			v.risk
		FROM container_instances ci
		JOIN container_images img ON ci.image_id = img.id
		JOIN vulnerabilities v ON img.id = v.image_id
		WHERE img.status = 'completed'
		ORDER BY ci.namespace, ci.pod, ci.container, v.severity, v.cve_id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability instances: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Warning: Failed to close rows: %v", err)
		}
	}()

	var instances []VulnerabilityInstance
	for rows.Next() {
		var instance VulnerabilityInstance
		err := rows.Scan(
			&instance.VulnID,
			&instance.Namespace,
			&instance.Pod,
			&instance.Container,
			&instance.NodeName,
			&instance.Repository,
			&instance.Tag,
			&instance.Digest,
			&instance.OSName,
			&instance.CVEID,
			&instance.PackageName,
			&instance.PackageVersion,
			&instance.Severity,
			&instance.FixStatus,
			&instance.FixedVersion,
			&instance.Count,
			&instance.KnownExploited,
			&instance.Risk,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability instance row: %w", err)
		}
		instances = append(instances, instance)
	}

	return instances, nil
}
