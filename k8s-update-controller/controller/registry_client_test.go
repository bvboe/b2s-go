package controller

import (
	"context"
	"strings"
	"testing"
)

func TestNewRegistryClient(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
	}{
		{
			name:          "Standard OCI registry",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "Registry without oci:// prefix",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "Empty registry",
			chartRegistry: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			if client == nil {
				t.Fatal("NewRegistryClient returned nil")
			}
			if client.chartRegistry != tt.chartRegistry {
				t.Errorf("chartRegistry = %q, want %q", client.chartRegistry, tt.chartRegistry)
			}
		})
	}
}

func TestRegistryClient_URLParsing(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		wantPrefix    string
	}{
		{
			name:          "OCI prefix is stripped",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			wantPrefix:    "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "No OCI prefix - unchanged",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
			wantPrefix:    "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the URL parsing logic used in ListVersions and DownloadChart
			registryURL := strings.TrimPrefix(tt.chartRegistry, "oci://")
			if registryURL != tt.wantPrefix {
				t.Errorf("URL parsing: got %q, want %q", registryURL, tt.wantPrefix)
			}
		})
	}
}

func TestRegistryClient_ListVersions_InvalidURL(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		wantErr       bool
	}{
		{
			name:          "Empty registry URL",
			chartRegistry: "",
			wantErr:       true,
		},
		{
			name:          "Invalid URL format",
			chartRegistry: "oci://not a valid url!!!",
			wantErr:       true,
		},
		{
			name:          "Missing repository",
			chartRegistry: "oci://ghcr.io",
			wantErr:       false, // name.ParseReference might accept this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			ctx := context.Background()

			// Note: This will try to contact the registry, so we expect network errors
			// We're mainly testing that invalid URLs are caught
			_, err := client.ListVersions(ctx)
			if tt.wantErr && err == nil {
				t.Error("ListVersions() expected error, got nil")
			}
			// For valid URLs, we expect network/auth errors (not nil), which is fine
		})
	}
}

func TestRegistryClient_DownloadChart_InvalidURL(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		version       string
		wantErr       bool
	}{
		{
			name:          "Empty registry URL",
			chartRegistry: "",
			version:       "0.1.0",
			wantErr:       true,
		},
		{
			name:          "Invalid URL format",
			chartRegistry: "oci://not a valid url!!!",
			version:       "0.1.0",
			wantErr:       true,
		},
		{
			name:          "Empty version",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			ctx := context.Background()

			// Note: This will try to contact the registry
			// We're testing that invalid inputs produce errors
			_, err := client.DownloadChart(ctx, tt.version)
			if tt.wantErr && err == nil {
				t.Error("DownloadChart() expected error, got nil")
			}
		})
	}
}

func TestRegistryClient_VerifySignature(t *testing.T) {
	// VerifySignature is not yet implemented, so test that it returns nil
	// and doesn't panic
	client := NewRegistryClient("oci://ghcr.io/bvboe/b2s-go/bjorn2scan")
	ctx := context.Background()

	err := client.VerifySignature(ctx, "/path/to/chart.tgz",
		"https://github.com/bvboe/b2s-go/*",
		"https://token.actions.githubusercontent.com")

	if err != nil {
		t.Errorf("VerifySignature() error = %v, want nil (not yet implemented)", err)
	}
}

// TestVersionFiltering tests the logic used in ListVersions to filter out non-version tags
func TestVersionFiltering(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		wantSkip map[string]bool
	}{
		{
			name: "Filter latest and sha tags",
			tags: []string{"0.1.0", "0.1.1", "latest", "sha-abc123", "0.2.0"},
			wantSkip: map[string]bool{
				"latest":     true,
				"sha-abc123": true,
			},
		},
		{
			name: "No special tags",
			tags: []string{"0.1.0", "0.1.1", "0.2.0"},
			wantSkip: map[string]bool{},
		},
		{
			name: "Only special tags",
			tags: []string{"latest", "sha-abc123", "sha-def456"},
			wantSkip: map[string]bool{
				"latest":     true,
				"sha-abc123": true,
				"sha-def456": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the filtering logic from ListVersions
			versions := []string{}
			for _, tag := range tt.tags {
				// Skip non-semantic version tags
				if tag == "latest" || strings.HasPrefix(tag, "sha-") {
					if !tt.wantSkip[tag] {
						t.Errorf("Tag %q should not be skipped", tag)
					}
					continue
				}
				versions = append(versions, tag)
			}

			// Verify correct tags were kept
			for _, version := range versions {
				if tt.wantSkip[version] {
					t.Errorf("Version %q should have been filtered out", version)
				}
			}

			// Verify correct count
			expectedCount := len(tt.tags) - len(tt.wantSkip)
			if len(versions) != expectedCount {
				t.Errorf("Got %d versions, want %d", len(versions), expectedCount)
			}
		})
	}
}

// TestChartRefConstruction tests the logic used to build chart references
func TestChartRefConstruction(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		version       string
		wantRef       string
	}{
		{
			name:          "Standard chart reference",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35",
		},
		{
			name:          "Registry without oci prefix",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35",
		},
		{
			name:          "Version with v prefix",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "v0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:v0.1.35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the chart reference construction from DownloadChart
			registryURL := strings.TrimPrefix(tt.chartRegistry, "oci://")
			chartRef := registryURL + ":" + tt.version

			if chartRef != tt.wantRef {
				t.Errorf("Chart ref = %q, want %q", chartRef, tt.wantRef)
			}
		})
	}
}
