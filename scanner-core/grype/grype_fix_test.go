package grype

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestScanWithDistro(t *testing.T) {
	// Read the nginx SBOM
	sbomPath := "../../dev-local/problem-scan/sbom_sha256__23b4dcdf0d34.json"
	sbomJSON, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Skipf("Skipping test: could not read SBOM file: %v", err)
		return
	}

	// Scan for vulnerabilities
	ctx := context.Background()
	scanResult, err := ScanVulnerabilities(ctx, sbomJSON)
	if err != nil {
		t.Fatalf("Failed to scan vulnerabilities: %v", err)
	}

	// Parse the result
	var result map[string]interface{}
	if err := json.Unmarshal(scanResult.VulnerabilityJSON, &result); err != nil {
		t.Fatalf("Failed to parse vulnerability JSON: %v", err)
	}

	// Check that we have matches
	matches, ok := result["matches"].([]interface{})
	if !ok {
		t.Fatal("No matches field in result")
	}

	matchCount := len(matches)
	t.Logf("Found %d vulnerability matches", matchCount)

	// Check distro in result
	if distro, ok := result["distro"].(map[string]interface{}); ok {
		t.Logf("Distro: name=%v, version=%v", distro["name"], distro["version"])

		// Verify distro is populated
		if name, ok := distro["name"].(string); !ok || name == "" {
			t.Error("Distro name is empty")
		}
	} else {
		t.Error("No distro field in result")
	}

	// We expect significantly more than 7 vulnerabilities for nginx:1.15
	if matchCount < 100 {
		t.Errorf("Expected at least 100 vulnerabilities, got %d", matchCount)
	}
}
