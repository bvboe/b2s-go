package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultFeedURL is the Anchore Grype vulnerability database feed URL
	DefaultFeedURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"

	// GrypeSchemaVersion is the current Grype database schema version
	GrypeSchemaVersion = "5"

	// CacheFilename is the name of the cache file
	CacheFilename = "grype_feed_cache.json"
)

// FeedListing represents the Anchore database feed listing
type FeedListing struct {
	Available map[string][]DatabaseEntry `json:"available"`
}

// DatabaseEntry represents a single database entry in the feed
type DatabaseEntry struct {
	Built    string `json:"built"`
	Checksum string `json:"checksum"`
	URL      string `json:"url"`
	Version  int    `json:"version"`
}

// CachedListing includes the listing and metadata
type CachedListing struct {
	LastChecked time.Time   `json:"last_checked"`
	Listing     FeedListing `json:"listing"`
}

// FeedChecker monitors the Grype vulnerability database feed
type FeedChecker struct {
	feedURL    string
	cacheFile  string
	httpClient *http.Client
	mu         sync.Mutex
}

// NewFeedChecker creates a new feed checker
// cacheDir is the directory where the cache file will be stored (typically the same as Grype's database directory)
func NewFeedChecker(cacheDir string) (*FeedChecker, error) {
	if cacheDir == "" {
		return nil, fmt.Errorf("cacheDir cannot be empty")
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cacheFile := filepath.Join(cacheDir, CacheFilename)

	return &FeedChecker{
		feedURL:   DefaultFeedURL,
		cacheFile: cacheFile,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}, nil
}

// CheckForUpdates fetches the feed and compares to cache
// Returns: (hasChanged bool, error)
// On first run (no cache), it returns (false, nil) after creating the cache
func (fc *FeedChecker) CheckForUpdates(ctx context.Context) (bool, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// 1. Fetch current listing from Anchore
	currentListing, err := fc.fetchListing(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to fetch listing: %w", err)
	}

	// 2. Load cached listing (if exists)
	cached, err := fc.loadCache()
	if err != nil {
		// First run - save listing and return false (don't trigger rescan)
		if os.IsNotExist(err) {
			log.Println("[feed-checker] First run detected, caching listing without triggering rescan")
			if saveErr := fc.saveCache(*currentListing); saveErr != nil {
				return false, fmt.Errorf("failed to save initial cache: %w", saveErr)
			}
			return false, nil
		}
		return false, fmt.Errorf("failed to load cache: %w", err)
	}

	// 3. Get latest checksum from both listings
	cachedChecksum := fc.getLatestChecksum(cached.Listing, GrypeSchemaVersion)
	currentChecksum := fc.getLatestChecksum(*currentListing, GrypeSchemaVersion)

	// 4. Compare checksums
	hasChanged := cachedChecksum != currentChecksum && cachedChecksum != "" && currentChecksum != ""

	// 5. Save current listing to cache
	if err := fc.saveCache(*currentListing); err != nil {
		return hasChanged, fmt.Errorf("failed to save cache: %w", err)
	}

	if hasChanged {
		log.Printf("[feed-checker] Database update detected: %s -> %s", cachedChecksum, currentChecksum)
	} else {
		log.Println("[feed-checker] No database changes detected")
	}

	return hasChanged, nil
}

// fetchListing retrieves the current feed from Anchore
func (fc *FeedChecker) fetchListing(ctx context.Context) (*FeedListing, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fc.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := fc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("[feed-checker] Warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON
	var listing FeedListing
	if err := json.Unmarshal(body, &listing); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &listing, nil
}

// loadCache reads the cached listing from disk
func (fc *FeedChecker) loadCache() (*CachedListing, error) {
	data, err := os.ReadFile(fc.cacheFile)
	if err != nil {
		return nil, err
	}

	var cached CachedListing
	if err := json.Unmarshal(data, &cached); err != nil {
		// Treat corrupted cache as first run - delete and recreate
		log.Printf("[feed-checker] Warning: corrupted cache, recreating: %v", err)
		if removeErr := os.Remove(fc.cacheFile); removeErr != nil {
			log.Printf("[feed-checker] Warning: failed to remove corrupted cache: %v", removeErr)
		}
		return nil, os.ErrNotExist
	}

	return &cached, nil
}

// saveCache writes the listing to disk atomically
func (fc *FeedChecker) saveCache(listing FeedListing) error {
	cached := CachedListing{
		LastChecked: time.Now().UTC(),
		Listing:     listing,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := fc.cacheFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, fc.cacheFile); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// getLatestChecksum returns the checksum of the most recent database for the given schema version
func (fc *FeedChecker) getLatestChecksum(listing FeedListing, schemaVersion string) string {
	entries, ok := listing.Available[schemaVersion]
	if !ok || len(entries) == 0 {
		log.Printf("[feed-checker] Warning: no entries for schema version %s", schemaVersion)
		return ""
	}

	// Entries are sorted newest first (by convention)
	return entries[0].Checksum
}
