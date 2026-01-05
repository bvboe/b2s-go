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
	// DefaultFeedURL is the Grype v6 vulnerability database feed URL
	// This endpoint returns the latest database info for schema v6
	DefaultFeedURL = "https://grype.anchore.io/databases/v6/latest.json"

	// CacheFilename is the name of the cache file
	CacheFilename = "grype_feed_cache_v6.json"
)

// DatabaseInfo represents the v6 database feed response
type DatabaseInfo struct {
	Status        string `json:"status"`
	SchemaVersion string `json:"schemaVersion"`
	Built         string `json:"built"`
	Path          string `json:"path"`
	Checksum      string `json:"checksum"`
}

// CachedDatabaseInfo includes the database info and metadata
type CachedDatabaseInfo struct {
	LastChecked  time.Time    `json:"last_checked"`
	DatabaseInfo DatabaseInfo `json:"database_info"`
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

	// 1. Fetch current database info from Anchore
	currentInfo, err := fc.fetchDatabaseInfo(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to fetch database info: %w", err)
	}

	log.Printf("[feed-checker] Current database: schema=%s, built=%s, checksum=%s",
		currentInfo.SchemaVersion, currentInfo.Built, truncateChecksum(currentInfo.Checksum))

	// 2. Load cached info (if exists)
	cached, err := fc.loadCache()
	if err != nil {
		// First run - save info and return false (don't trigger rescan)
		if os.IsNotExist(err) {
			log.Println("[feed-checker] First run detected, caching database info without triggering rescan")
			if saveErr := fc.saveCache(*currentInfo); saveErr != nil {
				return false, fmt.Errorf("failed to save initial cache: %w", saveErr)
			}
			return false, nil
		}
		return false, fmt.Errorf("failed to load cache: %w", err)
	}

	// 3. Compare checksums
	cachedChecksum := cached.DatabaseInfo.Checksum
	currentChecksum := currentInfo.Checksum

	hasChanged := cachedChecksum != currentChecksum && cachedChecksum != "" && currentChecksum != ""

	// 4. Save current info to cache
	if err := fc.saveCache(*currentInfo); err != nil {
		return hasChanged, fmt.Errorf("failed to save cache: %w", err)
	}

	if hasChanged {
		log.Printf("[feed-checker] Database update detected: %s -> %s",
			truncateChecksum(cachedChecksum), truncateChecksum(currentChecksum))
		log.Printf("[feed-checker] New database built: %s", currentInfo.Built)
	} else {
		log.Println("[feed-checker] No database changes detected")
	}

	return hasChanged, nil
}

// fetchDatabaseInfo retrieves the current database info from Anchore
func (fc *FeedChecker) fetchDatabaseInfo(ctx context.Context) (*DatabaseInfo, error) {
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
	var info DatabaseInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate response
	if info.Checksum == "" {
		return nil, fmt.Errorf("invalid response: missing checksum")
	}

	return &info, nil
}

// loadCache reads the cached database info from disk
func (fc *FeedChecker) loadCache() (*CachedDatabaseInfo, error) {
	data, err := os.ReadFile(fc.cacheFile)
	if err != nil {
		return nil, err
	}

	var cached CachedDatabaseInfo
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

// saveCache writes the database info to disk atomically
func (fc *FeedChecker) saveCache(info DatabaseInfo) error {
	cached := CachedDatabaseInfo{
		LastChecked:  time.Now().UTC(),
		DatabaseInfo: info,
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

// truncateChecksum returns a shortened version of the checksum for logging
func truncateChecksum(checksum string) string {
	if len(checksum) > 20 {
		return checksum[:20] + "..."
	}
	return checksum
}
