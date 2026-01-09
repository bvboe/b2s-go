package metrics

import (
	"math"
	"testing"
	"time"
)

// mockStore is a simple in-memory store for testing
type mockStore struct {
	data map[string]string
}

func newMockStore() *mockStore {
	return &mockStore{data: make(map[string]string)}
}

func (s *mockStore) LoadMetricStaleness(key string) (string, error) {
	return s.data[key], nil
}

func (s *mockStore) SaveMetricStaleness(key string, data string) error {
	s.data[key] = data
	return nil
}

func TestNewMetricTracker(t *testing.T) {
	mt := NewMetricTracker(MetricTrackerConfig{})

	if mt.stalenessWindow != DefaultStalenessWindow {
		t.Errorf("Expected default staleness window %v, got %v", DefaultStalenessWindow, mt.stalenessWindow)
	}

	if mt.storageKey != "metrics" {
		t.Errorf("Expected default storage key 'metrics', got %s", mt.storageKey)
	}

	if mt.lastSeen == nil {
		t.Error("lastSeen map should be initialized")
	}
}

func TestNewMetricTracker_CustomConfig(t *testing.T) {
	store := newMockStore()
	mt := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: 30 * time.Minute,
		Store:           store,
		StorageKey:      "custom_key",
	})

	if mt.stalenessWindow != 30*time.Minute {
		t.Errorf("Expected staleness window 30m, got %v", mt.stalenessWindow)
	}

	if mt.storageKey != "custom_key" {
		t.Errorf("Expected storage key 'custom_key', got %s", mt.storageKey)
	}
}

func TestGenerateMetricKey(t *testing.T) {
	tests := []struct {
		name       string
		familyName string
		labels     map[string]string
		expected   string
	}{
		{
			name:       "no labels",
			familyName: "my_metric",
			labels:     map[string]string{},
			expected:   "my_metric",
		},
		{
			name:       "single label",
			familyName: "my_metric",
			labels:     map[string]string{"key": "value"},
			expected:   "my_metric|key=value",
		},
		{
			name:       "multiple labels sorted",
			familyName: "my_metric",
			labels:     map[string]string{"z": "last", "a": "first", "m": "middle"},
			expected:   "my_metric|a=first|m=middle|z=last",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateMetricKey(tt.familyName, tt.labels)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestParseMetricKey(t *testing.T) {
	tests := []struct {
		name           string
		key            string
		expectedFamily string
		expectedLabels map[string]string
	}{
		{
			name:           "no labels",
			key:            "my_metric",
			expectedFamily: "my_metric",
			expectedLabels: map[string]string{},
		},
		{
			name:           "single label",
			key:            "my_metric|key=value",
			expectedFamily: "my_metric",
			expectedLabels: map[string]string{"key": "value"},
		},
		{
			name:           "multiple labels",
			key:            "my_metric|a=first|m=middle|z=last",
			expectedFamily: "my_metric",
			expectedLabels: map[string]string{"a": "first", "m": "middle", "z": "last"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			family, labels := parseMetricKey(tt.key)
			if family != tt.expectedFamily {
				t.Errorf("Expected family %q, got %q", tt.expectedFamily, family)
			}
			if len(labels) != len(tt.expectedLabels) {
				t.Errorf("Expected %d labels, got %d", len(tt.expectedLabels), len(labels))
			}
			for k, v := range tt.expectedLabels {
				if labels[k] != v {
					t.Errorf("Expected label %s=%s, got %s", k, v, labels[k])
				}
			}
		})
	}
}

func TestProcessMetrics_NewMetrics(t *testing.T) {
	store := newMockStore()
	mt := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: time.Hour,
		Store:           store,
	})

	data := &MetricsData{
		Families: []MetricFamily{
			{
				Name: "test_metric",
				Help: "Test metric",
				Type: "gauge",
				Metrics: []MetricPoint{
					{Labels: map[string]string{"pod": "pod1"}, Value: 1},
					{Labels: map[string]string{"pod": "pod2"}, Value: 1},
				},
			},
		},
	}

	result := mt.ProcessMetrics(data)

	// Should have 2 metrics tracked
	if mt.GetTrackedCount() != 2 {
		t.Errorf("Expected 2 tracked metrics, got %d", mt.GetTrackedCount())
	}

	// No stale metrics should be added
	if len(result.Families[0].Metrics) != 2 {
		t.Errorf("Expected 2 metrics, got %d", len(result.Families[0].Metrics))
	}
}

func TestProcessMetrics_StaleMetrics(t *testing.T) {
	store := newMockStore()
	mt := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: 100 * time.Millisecond, // Very short for testing
		Store:           store,
	})

	// First call with 2 metrics
	data1 := &MetricsData{
		Families: []MetricFamily{
			{
				Name: "test_metric",
				Help: "Test metric",
				Type: "gauge",
				Metrics: []MetricPoint{
					{Labels: map[string]string{"pod": "pod1"}, Value: 1},
					{Labels: map[string]string{"pod": "pod2"}, Value: 1},
				},
			},
		},
	}
	mt.ProcessMetrics(data1)

	// Wait for staleness window to pass
	time.Sleep(150 * time.Millisecond)

	// Second call with only 1 metric (pod2 is gone)
	data2 := &MetricsData{
		Families: []MetricFamily{
			{
				Name: "test_metric",
				Help: "Test metric",
				Type: "gauge",
				Metrics: []MetricPoint{
					{Labels: map[string]string{"pod": "pod1"}, Value: 1},
				},
			},
		},
	}
	result := mt.ProcessMetrics(data2)

	// Should have stale metric for pod2 with NaN
	if len(result.Families[0].Metrics) != 2 {
		t.Errorf("Expected 2 metrics (1 current + 1 stale), got %d", len(result.Families[0].Metrics))
	}

	// Find the stale metric
	foundStale := false
	for _, m := range result.Families[0].Metrics {
		if m.Labels["pod"] == "pod2" {
			if !math.IsNaN(m.Value) {
				t.Errorf("Expected NaN value for stale metric, got %f", m.Value)
			}
			foundStale = true
		}
	}
	if !foundStale {
		t.Error("Expected to find stale metric for pod2")
	}

	// Stale metric should be removed from tracking
	if mt.GetTrackedCount() != 1 {
		t.Errorf("Expected 1 tracked metric after stale removal, got %d", mt.GetTrackedCount())
	}
}

func TestProcessMetrics_Persistence(t *testing.T) {
	store := newMockStore()

	// Create tracker and add some metrics
	mt1 := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: time.Hour,
		Store:           store,
	})

	data := &MetricsData{
		Families: []MetricFamily{
			{
				Name: "test_metric",
				Help: "Test metric",
				Type: "gauge",
				Metrics: []MetricPoint{
					{Labels: map[string]string{"pod": "pod1"}, Value: 1},
				},
			},
		},
	}
	mt1.ProcessMetrics(data)

	// Verify data was persisted
	if store.data["metrics"] == "" {
		t.Error("Expected data to be persisted")
	}

	// Create new tracker from same store (simulating restart)
	mt2 := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: time.Hour,
		Store:           store,
	})

	// Should have loaded the persisted data
	if mt2.GetTrackedCount() != 1 {
		t.Errorf("Expected 1 tracked metric from persistence, got %d", mt2.GetTrackedCount())
	}
}

func TestProcessMetrics_NilData(t *testing.T) {
	mt := NewMetricTracker(MetricTrackerConfig{})

	result := mt.ProcessMetrics(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestProcessMetrics_OnlyWritesOnChange(t *testing.T) {
	store := newMockStore()
	mt := NewMetricTracker(MetricTrackerConfig{
		StalenessWindow: time.Hour,
		Store:           store,
	})

	data := &MetricsData{
		Families: []MetricFamily{
			{
				Name: "test_metric",
				Help: "Test metric",
				Type: "gauge",
				Metrics: []MetricPoint{
					{Labels: map[string]string{"pod": "pod1"}, Value: 1},
				},
			},
		},
	}

	// First call should persist
	mt.ProcessMetrics(data)
	firstSave := store.data["metrics"]

	// Second call with same metrics should not change persisted data
	mt.ProcessMetrics(data)
	secondSave := store.data["metrics"]

	if firstSave != secondSave {
		t.Error("Data should not have changed on second call with same metrics")
	}
}
