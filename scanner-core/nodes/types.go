package nodes

import "time"

// Node represents a Kubernetes node being scanned for vulnerabilities
type Node struct {
	// Name is the Kubernetes node name (unique identifier)
	Name string `json:"name"`
	// Hostname is the node's hostname from node info
	Hostname string `json:"hostname,omitempty"`
	// OSRelease is the OS release string (e.g., "Ubuntu 22.04.3 LTS")
	OSRelease string `json:"os_release,omitempty"`
	// KernelVersion is the kernel version string
	KernelVersion string `json:"kernel_version,omitempty"`
	// Architecture is the CPU architecture (e.g., "amd64", "arm64")
	Architecture string `json:"architecture,omitempty"`
	// ContainerRuntime is the container runtime on this node (e.g., "containerd://1.7.0")
	ContainerRuntime string `json:"container_runtime,omitempty"`
	// KubeletVersion is the kubelet version on this node
	KubeletVersion string `json:"kubelet_version,omitempty"`
}

// NodeScanStatus represents the current scan status of a node
type NodeScanStatus struct {
	// Status is the current scan status (pending, generating_sbom, scanning_vulnerabilities, completed, failed)
	Status string `json:"status"`
	// StatusError contains error details if status is failed
	StatusError string `json:"status_error,omitempty"`
	// SBOMScannedAt is when the SBOM was last generated
	SBOMScannedAt *time.Time `json:"sbom_scanned_at,omitempty"`
	// VulnsScannedAt is when vulnerabilities were last scanned
	VulnsScannedAt *time.Time `json:"vulns_scanned_at,omitempty"`
	// GrypeDBBuilt is the build timestamp of the grype DB used for the last scan
	GrypeDBBuilt *time.Time `json:"grype_db_built,omitempty"`
}

// NodeWithStatus combines node info with scan status
type NodeWithStatus struct {
	Node
	NodeScanStatus
	// PackageCount is the number of packages found on this node
	PackageCount int `json:"package_count"`
	// VulnerabilityCount is the total number of vulnerabilities found
	VulnerabilityCount int `json:"vulnerability_count"`
	// CreatedAt is when the node was first tracked
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the node was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// NodePackage represents a package installed on a node
type NodePackage struct {
	ID      int64  `json:"id"`
	NodeID  int64  `json:"node_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	// Language is the package language (for language-specific packages)
	Language string `json:"language,omitempty"`
	// PURL is the package URL
	PURL string `json:"purl,omitempty"`
	// Details contains additional package metadata as JSON
	Details string `json:"details,omitempty"`
	// VulnCount is the number of vulnerabilities associated with this package
	VulnCount int `json:"count"`
}

// NodeVulnerability represents a vulnerability found on a node
type NodeVulnerability struct {
	ID        int64  `json:"id"`
	NodeID    int64  `json:"node_id"`
	PackageID int64  `json:"package_id"`
	CVEID     string `json:"cve_id"`
	Severity  string `json:"severity"`
	// Score is the CVSS score
	Score float64 `json:"score,omitempty"`
	// FixStatus indicates if a fix is available (fixed, not-fixed, unknown)
	FixStatus string `json:"fix_status,omitempty"`
	// FixVersion is the version that fixes this vulnerability
	FixVersion string `json:"fix_version,omitempty"`
	// KnownExploited indicates if this vulnerability is in CISA KEV catalog
	KnownExploited bool `json:"known_exploited"`
	// Details contains additional vulnerability metadata as JSON
	Details   string    `json:"details,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// NodeSummary provides aggregated vulnerability counts by severity
type NodeSummary struct {
	NodeName     string `json:"node_name"`
	OSRelease    string `json:"os_release"`
	PackageCount int    `json:"package_count"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	Medium       int    `json:"medium"`
	Low          int    `json:"low"`
	Negligible   int    `json:"negligible"`
	Unknown      int    `json:"unknown"`
	Total        int    `json:"total"`
}

// NodeDistributionSummary provides averaged vulnerability counts grouped by OS distribution
type NodeDistributionSummary struct {
	OSName        string  `json:"os_name"`
	NodeCount     int     `json:"node_count"`
	AvgCritical   float64 `json:"avg_critical"`
	AvgHigh       float64 `json:"avg_high"`
	AvgMedium     float64 `json:"avg_medium"`
	AvgLow        float64 `json:"avg_low"`
	AvgNegligible float64 `json:"avg_negligible"`
	AvgUnknown    float64 `json:"avg_unknown"`
	AvgPackages   float64 `json:"avg_packages"`
}
