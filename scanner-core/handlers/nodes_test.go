package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// createTestDBForHandlers creates a temporary test database
func createTestDBForHandlers(t *testing.T) (*database.DB, func()) {
	t.Helper()
	dbPath := "/tmp/test_handlers_nodes_" + time.Now().Format("20060102150405.000") + ".db"
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	cleanup := func() {
		_ = database.Close(db)
		_ = os.Remove(dbPath)
	}
	return db, cleanup
}

// TestListNodesHandler_ReturnsEmptyList tests empty node list
func TestListNodesHandler_ReturnsEmptyList(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := ListNodesHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var result []nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Empty list should have length 0 (may be null or [] in JSON)
	if len(result) != 0 {
		t.Errorf("Expected empty list, got %d nodes", len(result))
	}
}

// TestListNodesHandler_ReturnsNodes tests listing nodes
func TestListNodesHandler_ReturnsNodes(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	// Add test nodes
	_, _ = db.AddNode(nodes.Node{Name: "node-1", Hostname: "node-1.local"})
	_, _ = db.AddNode(nodes.Node{Name: "node-2", Hostname: "node-2.local"})

	handler := ListNodesHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(result))
	}
}

// TestListNodesHandler_RejectsNonGet tests that non-GET methods are rejected
func TestListNodesHandler_RejectsNonGet(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := ListNodesHandler(db)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/nodes", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Method %s: Expected status 405, got %d", method, w.Code)
		}
	}
}

// TestNodeDetailHandler_ReturnsNode tests getting a single node
func TestNodeDetailHandler_ReturnsNode(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{
		Name:         "test-node",
		Hostname:     "test-node.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	})

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if result.Name != "test-node" {
		t.Errorf("Expected name=test-node, got %s", result.Name)
	}
	if result.Hostname != "test-node.local" {
		t.Errorf("Expected hostname=test-node.local, got %s", result.Hostname)
	}
}

// TestNodeDetailHandler_ReturnsNotFound tests 404 for missing node
func TestNodeDetailHandler_ReturnsNotFound(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/nonexistent", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestNodeDetailHandler_RequiresNodeName tests that node name is required
func TestNodeDetailHandler_RequiresNodeName(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestNodeDetailHandler_Packages tests getting node packages
func TestNodeDetailHandler_Packages(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb"},
		{"name": "curl", "version": "7.68.0", "type": "deb"}
	]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/packages", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodePackage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(result))
	}
}

// TestNodeDetailHandler_Vulnerabilities tests getting node vulnerabilities
func TestNodeDetailHandler_Vulnerabilities(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-5678", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/vulnerabilities", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeVulnerability
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(result))
	}
}

// TestNodeDetailHandler_UnknownSubresource tests 404 for unknown subresource
func TestNodeDetailHandler_UnknownSubresource(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/unknown", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestNodeSummaryHandler_ReturnsSummaries tests getting node summaries
func TestNodeSummaryHandler_ReturnsSummaries(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "node-1"})
	_, _ = db.AddNode(nodes.Node{Name: "node-2"})

	// Add packages and vulns to node-1
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0002", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeSummary
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 summaries, got %d", len(result))
	}

	// Find node-1 summary and verify counts
	for _, s := range result {
		if s.NodeName == "node-1" {
			if s.Critical != 1 {
				t.Errorf("node-1: Expected Critical=1, got %d", s.Critical)
			}
			if s.High != 1 {
				t.Errorf("node-1: Expected High=1, got %d", s.High)
			}
			if s.Total != 2 {
				t.Errorf("node-1: Expected Total=2, got %d", s.Total)
			}
		}
	}
}

// TestNodeSummaryHandler_RejectsNonGet tests that non-GET methods are rejected
func TestNodeSummaryHandler_RejectsNonGet(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodPost, "/api/summary/by-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestRegisterNodeHandlers_RegistersAllRoutes tests that all routes are registered
func TestRegisterNodeHandlers_RegistersAllRoutes(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	mux := http.NewServeMux()
	RegisterNodeHandlers(mux, db)

	// Test each route responds (not 404 from ServeMux)
	routes := []string{
		"/api/nodes",
		"/api/nodes/test-node",
		"/api/summary/by-node",
	}

	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Should not be 404 from mux (handler not found)
		// The actual response might be 404 (node not found) or 200, but not mux 404
		if w.Code == http.StatusNotFound && w.Body.String() == "404 page not found\n" {
			t.Errorf("Route %s not registered (got mux 404)", route)
		}
	}
}
