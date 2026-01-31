package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/k8s-scan-server/podscanner"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
	"k8s.io/client-go/kubernetes/fake"
)

// setupTestDB creates a temporary test database with sample data
func setupTestDB(t *testing.T) (*database.DB, string, func()) {
	dbPath := "/tmp/test_sbom_handler_" + time.Now().Format("20060102150405") + ".db"

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup := func() {
		_ = database.Close(db)
		_ = os.Remove(dbPath)
	}

	return db, dbPath, cleanup
}

// TestSBOMHandler_EmptyDigest tests that handler returns 400 for empty digest
func TestSBOMHandler_EmptyDigest(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Test with path that's too short
	req := httptest.NewRequest("GET", "/api/sbom/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body != "Digest required\n" {
		t.Errorf("Expected 'Digest required', got %q", body)
	}
}

// TestSBOMHandler_DigestNormalization tests that handler normalizes digest
func TestSBOMHandler_DigestNormalization(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	// Add test instance with image (use proper 64-char hex digest)
	testDigest := "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    testDigest,
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add test instance: %v", err)
	}

	// Store test SBOM
	testSBOM := []byte(`{"test": "sbom"}`)
	err = db.StoreSBOM(testDigest, testSBOM)
	if err != nil {
		t.Fatalf("Failed to store test SBOM: %v", err)
	}

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Test with digest WITHOUT sha256: prefix (should be normalized to match database)
	req := httptest.NewRequest("GET", "/api/sbom/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Verify we got the SBOM
	if rec.Body.String() != string(testSBOM) {
		t.Errorf("Expected SBOM content %q, got %q", string(testSBOM), rec.Body.String())
	}
}

// TestSBOMHandler_DatabaseCacheHit tests that handler serves from database cache
func TestSBOMHandler_DatabaseCacheHit(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	// Add test instance with image (use proper 64-char hex digest)
	testDigest := "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    testDigest,
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add test instance: %v", err)
	}

	// Store test SBOM in database (simulates scan queue cached SBOM)
	testSBOM := []byte(`{"cached": "sbom", "packages": ["pkg1", "pkg2"]}`)
	err = db.StoreSBOM(testDigest, testSBOM)
	if err != nil {
		t.Fatalf("Failed to store test SBOM: %v", err)
	}

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Request SBOM
	req := httptest.NewRequest("GET", "/api/sbom/"+testDigest, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	if rec.Body.String() != string(testSBOM) {
		t.Errorf("Expected SBOM %q, got %q", string(testSBOM), rec.Body.String())
	}

	// Verify headers
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %q", contentType)
	}

	contentDisposition := rec.Header().Get("Content-Disposition")
	if contentDisposition == "" {
		t.Error("Expected Content-Disposition header to be set")
	}

	contentLength := rec.Header().Get("Content-Length")
	expectedLength := fmt.Sprintf("%d", len(testSBOM))
	if contentLength != expectedLength {
		t.Errorf("Expected Content-Length %q, got %q", expectedLength, contentLength)
	}
}

// TestSBOMHandler_ImageNotFound tests 404 when image not in database
func TestSBOMHandler_ImageNotFound(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Request SBOM for non-existent image
	req := httptest.NewRequest("GET", "/api/sbom/sha256:nonexistent", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body != "Image not found in cluster\n" {
		t.Errorf("Expected 'Image not found in cluster', got %q", body)
	}
}

// TestSBOMHandler_ImageWithoutNodeName tests 404 when image has no node name
func TestSBOMHandler_ImageWithoutNodeName(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	// Add instance without node name (simulates agent-scanned image)
	testDigest := "sha256:nonode123"
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    testDigest,
		},
		NodeName:         "", // No node name
		ContainerRuntime: "docker",
	}

	_, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add test instance: %v", err)
	}

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Request SBOM
	req := httptest.NewRequest("GET", "/api/sbom/"+testDigest, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body != "Image not available on any cluster node\n" {
		t.Errorf("Expected 'Image not available on any cluster node', got %q", body)
	}
}

// TestSBOMHandler_ContextTimeout tests timeout handling
func TestSBOMHandler_ContextTimeout(t *testing.T) {
	db, _, cleanup := setupTestDB(t)
	defer cleanup()

	clientset := fake.NewClientset()
	podScannerClient := podscanner.NewClient()

	// Add instance with node name (so it tries to route to pod-scanner)
	testDigest := "sha256:timeout123"
	instance := containers.ContainerInstance{
		ID: containers.ContainerInstanceID{
			Namespace: "default",
			Pod:       "test-pod",
			Container: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    testDigest,
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err := db.AddInstance(instance)
	if err != nil {
		t.Fatalf("Failed to add test instance: %v", err)
	}

	handler := SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient)

	// Create request with already-cancelled context (simulates timeout)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := httptest.NewRequest("GET", "/api/sbom/"+testDigest, nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should get timeout or internal error
	// (exact error depends on when the cancellation is detected)
	if rec.Code != http.StatusGatewayTimeout && rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 504 or 500, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestWriteSBOMResponse tests the writeSBOMResponse helper function
func TestWriteSBOMResponse(t *testing.T) {
	tests := []struct {
		name           string
		digest         string
		sbomData       []byte
		wantStatusCode int
	}{
		{
			name:           "Normal SBOM",
			digest:         "sha256:abc123",
			sbomData:       []byte(`{"test": "data"}`),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "Large digest",
			digest:         "sha256:abcdef1234567890abcdef1234567890abcdef1234567890",
			sbomData:       []byte(`{"large": "sbom"}`),
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "Empty SBOM",
			digest:         "sha256:empty",
			sbomData:       []byte{},
			wantStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			writeSBOMResponse(rec, tt.sbomData, tt.digest)

			// Check status (should be 200 by default since we call Write)
			if rec.Code != tt.wantStatusCode {
				t.Errorf("Expected status %d, got %d", tt.wantStatusCode, rec.Code)
			}

			// Check content
			if rec.Body.String() != string(tt.sbomData) {
				t.Errorf("Expected body %q, got %q", string(tt.sbomData), rec.Body.String())
			}

			// Check headers
			if contentType := rec.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("Expected Content-Type 'application/json', got %q", contentType)
			}

			if contentDisposition := rec.Header().Get("Content-Disposition"); contentDisposition == "" {
				t.Error("Expected Content-Disposition header to be set")
			}

			expectedLength := fmt.Sprintf("%d", len(tt.sbomData))
			if contentLength := rec.Header().Get("Content-Length"); contentLength != expectedLength {
				t.Errorf("Expected Content-Length %q, got %q", expectedLength, contentLength)
			}
		})
	}
}
