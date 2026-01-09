package metrics

import (
	"encoding/json"
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

// DefaultStalenessWindow is the default duration after which metrics are considered stale
const DefaultStalenessWindow = 60 * time.Minute

// MetricTrackerStore is the interface for persisting metric staleness data
type MetricTrackerStore interface {
	LoadMetricStaleness(key string) (string, error)
	SaveMetricStaleness(key string, data string) error
}

// MetricTracker tracks metric last-seen times for staleness detection
// It persists data to the database for survival across restarts
type MetricTracker struct {
	mu              sync.RWMutex
	lastSeen        map[string]time.Time // metric key -> last seen timestamp
	stalenessWindow time.Duration        // how long until a metric is considered stale
	store           MetricTrackerStore   // database interface for persistence
	storageKey      string               // key used for database storage
	lastSavedHash   string               // hash of last saved data to avoid unnecessary writes
}

// MetricTrackerConfig holds configuration for the MetricTracker
type MetricTrackerConfig struct {
	StalenessWindow time.Duration      // Duration after which metrics are stale (default: 60 min)
	Store           MetricTrackerStore // Database interface for persistence
	StorageKey      string             // Key used for database storage (default: "metrics")
}

// NewMetricTracker creates a new MetricTracker
func NewMetricTracker(cfg MetricTrackerConfig) *MetricTracker {
	if cfg.StalenessWindow == 0 {
		cfg.StalenessWindow = DefaultStalenessWindow
	}
	if cfg.StorageKey == "" {
		cfg.StorageKey = "metrics"
	}

	mt := &MetricTracker{
		lastSeen:        make(map[string]time.Time),
		stalenessWindow: cfg.StalenessWindow,
		store:           cfg.Store,
		storageKey:      cfg.StorageKey,
	}

	// Load persisted data from database
	if cfg.Store != nil {
		if err := mt.loadFromStore(); err != nil {
			log.Printf("[metric-tracker] Warning: failed to load persisted data: %v", err)
		}
	}

	return mt
}

// loadFromStore loads the last-seen data from the database
func (mt *MetricTracker) loadFromStore() error {
	data, err := mt.store.LoadMetricStaleness(mt.storageKey)
	if err != nil {
		return err
	}
	if data == "" {
		return nil // No data yet
	}

	// Parse JSON: map of metric key -> RFC3339 timestamp
	var timestamps map[string]string
	if err := json.Unmarshal([]byte(data), &timestamps); err != nil {
		return err
	}

	mt.mu.Lock()
	defer mt.mu.Unlock()

	for key, ts := range timestamps {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			log.Printf("[metric-tracker] Warning: invalid timestamp for key %s: %v", key, err)
			continue
		}
		mt.lastSeen[key] = t
	}

	log.Printf("[metric-tracker] Loaded %d metric timestamps from database", len(mt.lastSeen))
	return nil
}

// saveToStore persists the last-seen data to the database
// Only writes if data has changed
func (mt *MetricTracker) saveToStore() error {
	if mt.store == nil {
		return nil
	}

	mt.mu.RLock()
	// Convert to JSON-serializable format
	timestamps := make(map[string]string, len(mt.lastSeen))
	for key, t := range mt.lastSeen {
		timestamps[key] = t.Format(time.RFC3339)
	}
	mt.mu.RUnlock()

	data, err := json.Marshal(timestamps)
	if err != nil {
		return err
	}

	// Check if data has changed (simple string comparison)
	dataStr := string(data)
	if dataStr == mt.lastSavedHash {
		return nil // No change
	}

	if err := mt.store.SaveMetricStaleness(mt.storageKey, dataStr); err != nil {
		return err
	}

	mt.lastSavedHash = dataStr
	return nil
}

// generateMetricKey creates a unique key for a metric based on its name and labels
func generateMetricKey(familyName string, labels map[string]string) string {
	// Sort labels for consistent key generation
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := familyName
	for _, k := range keys {
		key += "|" + k + "=" + labels[k]
	}
	return key
}

// ProcessMetrics processes metrics data, updates last-seen times, and adds stale markers
// Returns the processed metrics data with stale metrics included
func (mt *MetricTracker) ProcessMetrics(data *MetricsData) *MetricsData {
	if data == nil {
		return nil
	}

	now := time.Now()
	currentMetrics := make(map[string]struct{})

	// Build set of current metrics and update last-seen times
	for _, family := range data.Families {
		for _, metric := range family.Metrics {
			key := generateMetricKey(family.Name, metric.Labels)
			currentMetrics[key] = struct{}{}
		}
	}

	// Update last-seen times for current metrics
	mt.mu.Lock()
	for key := range currentMetrics {
		mt.lastSeen[key] = now
	}

	// Find stale metrics (in lastSeen but not in current, and older than staleness window)
	staleMetrics := make(map[string]time.Time)
	expiredMetrics := make([]string, 0)
	staleThreshold := now.Add(-mt.stalenessWindow)

	for key, lastTime := range mt.lastSeen {
		if _, exists := currentMetrics[key]; !exists {
			if lastTime.Before(staleThreshold) {
				// Metric is stale - mark for NaN emission and removal from tracking
				staleMetrics[key] = lastTime
				expiredMetrics = append(expiredMetrics, key)
			}
			// If not yet past staleness window, keep tracking but don't emit
		}
	}

	// Remove expired metrics from tracking
	for _, key := range expiredMetrics {
		delete(mt.lastSeen, key)
	}
	mt.mu.Unlock()

	// Persist to database (only if changed)
	if err := mt.saveToStore(); err != nil {
		log.Printf("[metric-tracker] Warning: failed to persist data: %v", err)
	}

	// Add stale metrics to the output with NaN value
	if len(staleMetrics) > 0 {
		data = mt.addStaleMetrics(data, staleMetrics)
		log.Printf("[metric-tracker] Marked %d metrics as stale", len(staleMetrics))
	}

	return data
}

// addStaleMetrics adds stale metrics to the data with NaN values
func (mt *MetricTracker) addStaleMetrics(data *MetricsData, staleMetrics map[string]time.Time) *MetricsData {
	// Parse stale metric keys and group by family
	staleByFamily := make(map[string][]MetricPoint)

	for key := range staleMetrics {
		familyName, labels := parseMetricKey(key)
		if familyName == "" {
			continue
		}
		staleByFamily[familyName] = append(staleByFamily[familyName], MetricPoint{
			Labels: labels,
			Value:  math.NaN(),
		})
	}

	// Add stale metrics to existing families or create new ones
	for i := range data.Families {
		family := &data.Families[i]
		if stalePoints, ok := staleByFamily[family.Name]; ok {
			family.Metrics = append(family.Metrics, stalePoints...)
			delete(staleByFamily, family.Name)
		}
	}

	// Add any remaining stale metrics as new families
	for familyName, points := range staleByFamily {
		data.Families = append(data.Families, MetricFamily{
			Name:    familyName,
			Help:    "Stale metric",
			Type:    "gauge",
			Metrics: points,
		})
	}

	return data
}

// parseMetricKey parses a metric key back into family name and labels
func parseMetricKey(key string) (string, map[string]string) {
	// Key format: familyName|label1=value1|label2=value2|...
	labels := make(map[string]string)

	// Find first separator
	firstSep := -1
	for i, c := range key {
		if c == '|' {
			firstSep = i
			break
		}
	}

	if firstSep == -1 {
		return key, labels // No labels
	}

	familyName := key[:firstSep]
	rest := key[firstSep+1:]

	// Parse remaining label pairs
	start := 0
	for i := 0; i <= len(rest); i++ {
		if i == len(rest) || rest[i] == '|' {
			pair := rest[start:i]
			eqIdx := -1
			for j, c := range pair {
				if c == '=' {
					eqIdx = j
					break
				}
			}
			if eqIdx > 0 {
				labels[pair[:eqIdx]] = pair[eqIdx+1:]
			}
			start = i + 1
		}
	}

	return familyName, labels
}

// GetStalenessWindow returns the configured staleness window
func (mt *MetricTracker) GetStalenessWindow() time.Duration {
	return mt.stalenessWindow
}

// GetTrackedCount returns the number of metrics currently being tracked
func (mt *MetricTracker) GetTrackedCount() int {
	mt.mu.RLock()
	defer mt.mu.RUnlock()
	return len(mt.lastSeen)
}
