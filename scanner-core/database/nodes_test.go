package database

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// createTestDB creates a temporary test database
func createTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	dbPath := "/tmp/test_nodes_" + time.Now().Format("20060102150405.000") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	cleanup := func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}
	return db, cleanup
}

// TestAddNode_CreatesNew tests that a new node is created
func TestAddNode_CreatesNew(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Hostname:     "test-node-1.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	}

	isNew, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	if !isNew {
		t.Error("Expected isNew=true for new node")
	}

	// Verify node exists in database
	var name string
	err = db.conn.QueryRow("SELECT name FROM nodes WHERE name = ?", node.Name).Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query node: %v", err)
	}

	if name != node.Name {
		t.Errorf("Name = %v, want %v", name, node.Name)
	}
}

// TestAddNode_UpdatesExisting tests that existing node is updated
func TestAddNode_UpdatesExisting(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Hostname:     "test-node-1.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	}

	// Create first time
	isNew1, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("First AddNode failed: %v", err)
	}
	if !isNew1 {
		t.Error("Expected isNew=true for first call")
	}

	// Update with new OS release
	node.OSRelease = "Ubuntu 24.04"
	isNew2, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("Second AddNode failed: %v", err)
	}

	if isNew2 {
		t.Error("Expected isNew=false for existing node")
	}

	// Verify OS release was updated
	var osRelease string
	err = db.conn.QueryRow("SELECT os_release FROM nodes WHERE name = ?", node.Name).Scan(&osRelease)
	if err != nil {
		t.Fatalf("Failed to query node: %v", err)
	}

	if osRelease != "Ubuntu 24.04" {
		t.Errorf("OSRelease = %v, want Ubuntu 24.04", osRelease)
	}
}

// TestGetNode_ReturnsNode tests retrieving an existing node
func TestGetNode_ReturnsNode(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:          "test-node-1",
		Hostname:      "test-node-1.local",
		OSRelease:     "Ubuntu 22.04",
		KernelVersion: "5.15.0",
		Architecture:  "amd64",
	}

	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != node.Name {
		t.Errorf("Name = %v, want %v", result.Name, node.Name)
	}
	if result.Hostname != node.Hostname {
		t.Errorf("Hostname = %v, want %v", result.Hostname, node.Hostname)
	}
	if result.OSRelease != node.OSRelease {
		t.Errorf("OSRelease = %v, want %v", result.OSRelease, node.OSRelease)
	}
	if result.Architecture != node.Architecture {
		t.Errorf("Architecture = %v, want %v", result.Architecture, node.Architecture)
	}
}

// TestGetNode_ReturnsNilForMissing tests that missing node returns nil
func TestGetNode_ReturnsNilForMissing(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	result, err := db.GetNode("nonexistent-node")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result != nil {
		t.Error("Expected nil result for missing node")
	}
}

// TestGetAllNodes_ReturnsAllNodes tests retrieving all nodes
func TestGetAllNodes_ReturnsAllNodes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Add multiple nodes
	for i := 1; i <= 3; i++ {
		node := nodes.Node{
			Name:         "test-node-" + string(rune('0'+i)),
			Architecture: "amd64",
		}
		_, err := db.AddNode(node)
		if err != nil {
			t.Fatalf("AddNode failed for node %d: %v", i, err)
		}
	}

	result, err := db.GetAllNodes()
	if err != nil {
		t.Fatalf("GetAllNodes failed: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(result))
	}
}

// TestRemoveNode_RemovesNodeAndData tests removing a node
func TestRemoveNode_RemovesNodeAndData(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Architecture: "amd64",
	}

	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.RemoveNode("test-node-1")
	if err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	// Verify node is gone
	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result after removal")
	}
}

// TestRemoveNode_NonexistentNode tests removing a nonexistent node
func TestRemoveNode_NonexistentNode(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	err := db.RemoveNode("nonexistent-node")
	if err != nil {
		t.Fatalf("RemoveNode should not fail for nonexistent node: %v", err)
	}
}

// TestUpdateNodeStatus tests updating node status
func TestUpdateNodeStatus(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.UpdateNodeStatus("test-node-1", StatusCompleted, "")
	if err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	status, err := db.GetNodeScanStatus("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeScanStatus failed: %v", err)
	}

	if status != "completed" {
		t.Errorf("Status = %v, want completed", status)
	}
}

// TestUpdateNodeStatus_WithError tests updating node status with error message
func TestUpdateNodeStatus_WithError(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.UpdateNodeStatus("test-node-1", StatusVulnScanFailed, "scan timeout")
	if err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result.Status != "vuln_scan_failed" {
		t.Errorf("Status = %v, want vuln_scan_failed", result.Status)
	}
	if result.StatusError != "scan timeout" {
		t.Errorf("StatusError = %v, want 'scan timeout'", result.StatusError)
	}
}

// TestStoreNodeSBOM tests storing SBOM packages for a node
func TestStoreNodeSBOM(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	// Create a mock SBOM
	sbom := struct {
		Artifacts []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		} `json:"artifacts"`
	}{
		Artifacts: []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		}{
			{Name: "openssl", Version: "1.1.1", Type: "deb", PURL: "pkg:deb/ubuntu/openssl@1.1.1"},
			{Name: "curl", Version: "7.68.0", Type: "deb", PURL: "pkg:deb/ubuntu/curl@7.68.0"},
			{Name: "bash", Version: "5.0", Type: "deb", PURL: "pkg:deb/ubuntu/bash@5.0"},
		},
	}

	sbomJSON, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("Failed to marshal SBOM: %v", err)
	}

	err = db.StoreNodeSBOM("test-node-1", sbomJSON)
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Verify packages were stored
	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}

	if len(packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(packages))
	}

	// Verify specific package
	found := false
	for _, pkg := range packages {
		if pkg.Name == "openssl" && pkg.Version == "1.1.1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find openssl package")
	}
}

// TestStoreNodeSBOM_ReplacesExisting tests that SBOM storage replaces existing packages
func TestStoreNodeSBOM_ReplacesExisting(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store first SBOM
	sbom1 := `{"artifacts": [{"name": "pkg1", "version": "1.0", "type": "deb"}]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom1))
	if err != nil {
		t.Fatalf("First StoreNodeSBOM failed: %v", err)
	}

	// Store second SBOM (should replace)
	sbom2 := `{"artifacts": [{"name": "pkg2", "version": "2.0", "type": "deb"}, {"name": "pkg3", "version": "3.0", "type": "deb"}]}`
	err = db.StoreNodeSBOM("test-node-1", []byte(sbom2))
	if err != nil {
		t.Fatalf("Second StoreNodeSBOM failed: %v", err)
	}

	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("Expected 2 packages after replacement, got %d", len(packages))
	}

	// Verify old package is gone
	for _, pkg := range packages {
		if pkg.Name == "pkg1" {
			t.Error("Old package pkg1 should have been removed")
		}
	}
}

// TestStoreNodeVulnerabilities tests storing vulnerabilities for a node
func TestStoreNodeVulnerabilities(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store SBOM first
	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb"},
		{"name": "curl", "version": "7.68.0", "type": "deb"}
	]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Create vulnerability report
	vulnReport := `{"matches": [
		{
			"vulnerability": {
				"id": "CVE-2021-1234",
				"severity": "High",
				"cvss": [{"score": 7.5}],
				"fix": {"state": "fixed", "versions": ["1.1.2"]}
			},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {
				"id": "CVE-2021-5678",
				"severity": "Critical",
				"cvss": [{"score": 9.8}],
				"fix": {"state": "not-fixed"}
			},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {
				"id": "CVE-2021-9999",
				"severity": "Medium",
				"cvss": [{"score": 5.0}]
			},
			"artifact": {"name": "curl", "version": "7.68.0", "type": "deb"}
		}
	]}`

	grypeDBBuilt := time.Now()
	err = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), grypeDBBuilt)
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	// Verify vulnerabilities were stored
	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}

	if len(vulns) != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", len(vulns))
	}

	// Verify node status updated to completed
	nodeResult, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if nodeResult.Status != "completed" {
		t.Errorf("Expected status=completed, got %s", nodeResult.Status)
	}
}

// TestStoreNodeVulnerabilities_BatchedInserts tests that large vulnerability counts are handled
func TestStoreNodeVulnerabilities_BatchedInserts(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store SBOM with one package
	sbom := `{"artifacts": [{"name": "testpkg", "version": "1.0", "type": "deb"}]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Create many vulnerabilities (more than batch size of 500)
	type vulnMatch struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	}

	matches := make([]vulnMatch, 1500)
	for i := 0; i < 1500; i++ {
		matches[i] = vulnMatch{
			Vulnerability: struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			}{
				ID:       "CVE-2021-" + string(rune('0'+i/1000)) + string(rune('0'+(i/100)%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10)),
				Severity: "Medium",
			},
			Artifact: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			}{
				Name:    "testpkg",
				Version: "1.0",
				Type:    "deb",
			},
		}
	}

	vulnReport := struct {
		Matches []vulnMatch `json:"matches"`
	}{Matches: matches}

	vulnJSON, err := json.Marshal(vulnReport)
	if err != nil {
		t.Fatalf("Failed to marshal vulnerabilities: %v", err)
	}

	grypeDBBuilt := time.Now()
	err = db.StoreNodeVulnerabilities("test-node-1", vulnJSON, grypeDBBuilt)
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities with batched inserts failed: %v", err)
	}

	// Verify all vulnerabilities were stored
	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}

	if len(vulns) != 1500 {
		t.Errorf("Expected 1500 vulnerabilities, got %d", len(vulns))
	}
}

// TestStoreNodeVulnerabilities_SkipsMissingPackages tests that vulns for missing packages are skipped
func TestStoreNodeVulnerabilities_SkipsMissingPackages(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store SBOM with only one package
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	// Vulnerability report with a package that doesn't exist in SBOM
	vulnReport := `{"matches": [
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High"},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {"id": "CVE-2021-5678", "severity": "High"},
			"artifact": {"name": "nonexistent", "version": "1.0", "type": "deb"}
		}
	]}`

	err := db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	vulns, _ := db.GetNodeVulnerabilities("test-node-1")
	if len(vulns) != 1 {
		t.Errorf("Expected 1 vulnerability (skipping missing package), got %d", len(vulns))
	}
}

// TestGetNodeSummaries tests getting vulnerability summaries
func TestGetNodeSummaries(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0002", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0003", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0004", "severity": "Medium"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0005", "severity": "Low"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	summaries, err := db.GetNodeSummaries()
	if err != nil {
		t.Fatalf("GetNodeSummaries failed: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(summaries))
	}

	s := summaries[0]
	if s.NodeName != "test-node-1" {
		t.Errorf("NodeName = %v, want test-node-1", s.NodeName)
	}
	if s.Critical != 2 {
		t.Errorf("Critical = %d, want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High = %d, want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium = %d, want 1", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("Low = %d, want 1", s.Low)
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
}

// TestIsNodeScanComplete tests checking if a node scan is complete
func TestIsNodeScanComplete(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Initially not complete
	complete, err := db.IsNodeScanComplete("test-node-1")
	if err != nil {
		t.Fatalf("IsNodeScanComplete failed: %v", err)
	}
	if complete {
		t.Error("Expected incomplete before SBOM storage")
	}

	// Add SBOM and vulnerabilities
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": []}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	// Should now be complete
	complete, err = db.IsNodeScanComplete("test-node-1")
	if err != nil {
		t.Fatalf("IsNodeScanComplete failed: %v", err)
	}
	if !complete {
		t.Error("Expected complete after SBOM and vuln storage")
	}
}

// TestGetNodesNeedingRescan tests finding nodes that need rescanning
func TestGetNodesNeedingRescan(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Create a completed node with old grype DB
	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	oldGrypeDB := time.Now().Add(-48 * time.Hour)
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(`{"matches": []}`), oldGrypeDB)

	// Query with newer grype DB time
	currentGrypeDB := time.Now()
	nodesToRescan, err := db.GetNodesNeedingRescan(currentGrypeDB)
	if err != nil {
		t.Fatalf("GetNodesNeedingRescan failed: %v", err)
	}

	if len(nodesToRescan) != 1 {
		t.Errorf("Expected 1 node needing rescan, got %d", len(nodesToRescan))
	}
}

// TestGetNodesNeedingRescan_ExcludesUpToDate tests that up-to-date nodes are excluded
func TestGetNodesNeedingRescan_ExcludesUpToDate(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	currentGrypeDB := time.Now()
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(`{"matches": []}`), currentGrypeDB)

	// Query with same grype DB time
	nodesToRescan, err := db.GetNodesNeedingRescan(currentGrypeDB)
	if err != nil {
		t.Fatalf("GetNodesNeedingRescan failed: %v", err)
	}

	if len(nodesToRescan) != 0 {
		t.Errorf("Expected 0 nodes needing rescan, got %d", len(nodesToRescan))
	}
}

// TestRemoveNode_CascadesDeleteToPackagesAndVulns tests that removal cascades
func TestRemoveNode_CascadesDeleteToPackagesAndVulns(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	// Verify data exists
	packages, _ := db.GetNodePackages("test-node-1")
	if len(packages) == 0 {
		t.Fatal("Expected packages before removal")
	}

	vulns, _ := db.GetNodeVulnerabilities("test-node-1")
	if len(vulns) == 0 {
		t.Fatal("Expected vulnerabilities before removal")
	}

	// Remove node
	err := db.RemoveNode("test-node-1")
	if err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	// Verify all data is gone
	var pkgCount, vulnCount int
	_ = db.conn.QueryRow("SELECT COUNT(*) FROM node_packages").Scan(&pkgCount)
	_ = db.conn.QueryRow("SELECT COUNT(*) FROM node_vulnerabilities").Scan(&vulnCount)

	if pkgCount != 0 {
		t.Errorf("Expected 0 packages after removal, got %d", pkgCount)
	}
	if vulnCount != 0 {
		t.Errorf("Expected 0 vulnerabilities after removal, got %d", vulnCount)
	}
}
