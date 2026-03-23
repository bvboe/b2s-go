package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// mockStalenessDB is an in-memory StalenessDB for testing.
// It is shared across tracker_test.go, handler_test.go, and otel_test.go
// since they all live in the same package.
// mu protects all fields because DeleteExpired runs in a goroutine concurrently with QueryStale.
type mockStalenessDB struct {
	mu      sync.Mutex
	rows    []database.StalenessRow
	upserts [][]database.StalenessRow
	deleted int64
	err     error
}

func (m *mockStalenessDB) QueryStaleness(cycleStart, windowSecs int64) ([]database.StalenessRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var stale []database.StalenessRow
	for _, r := range m.rows {
		if r.LastSeenUnix < cycleStart && r.LastSeenUnix >= cycleStart-windowSecs {
			stale = append(stale, r)
		}
	}
	return stale, nil
}

func (m *mockStalenessDB) UpsertStaleness(batch []database.StalenessRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.upserts = append(m.upserts, batch)
	for _, newRow := range batch {
		found := false
		for i, r := range m.rows {
			if r.MetricKey == newRow.MetricKey {
				m.rows[i] = newRow
				found = true
				break
			}
		}
		if !found {
			m.rows = append(m.rows, newRow)
		}
	}
	return nil
}

func (m *mockStalenessDB) DeleteExpiredStaleness(expireBefore int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.deleted = expireBefore
	var kept []database.StalenessRow
	for _, r := range m.rows {
		if r.LastSeenUnix >= expireBefore {
			kept = append(kept, r)
		}
	}
	m.rows = kept
	return nil
}

func TestNewStalenessStore_Defaults(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, 0) // zero → DefaultStalenessWindow

	if s.StalenessWindow() != DefaultStalenessWindow {
		t.Errorf("Expected default window %v, got %v", DefaultStalenessWindow, s.StalenessWindow())
	}
	if s.BatchSize() != defaultBatchSize {
		t.Errorf("Expected batch size %d, got %d", defaultBatchSize, s.BatchSize())
	}
}

func TestNewStalenessStore_CustomWindow(t *testing.T) {
	db := &mockStalenessDB{}
	window := 30 * time.Minute
	s := NewStalenessStore(db, window)

	if s.StalenessWindow() != window {
		t.Errorf("Expected window %v, got %v", window, s.StalenessWindow())
	}
}

func TestStalenessStore_QueryStale(t *testing.T) {
	cycleStart := time.Unix(2000000, 0)
	window := time.Hour

	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			// Within staleness window — should be returned
			{MetricKey: "stale_metric", FamilyName: "family1", LastSeenUnix: cycleStart.Unix() - 100},
			// Past the staleness window — should NOT be returned
			{MetricKey: "expired_metric", FamilyName: "family2", LastSeenUnix: cycleStart.Unix() - int64(window.Seconds()) - 1},
			// Same timestamp as cycleStart — not stale (current cycle)
			{MetricKey: "current_metric", FamilyName: "family3", LastSeenUnix: cycleStart.Unix()},
		},
	}

	s := NewStalenessStore(db, window)
	stale, err := s.QueryStale(cycleStart)
	if err != nil {
		t.Fatalf("QueryStale failed: %v", err)
	}

	if len(stale) != 1 {
		t.Fatalf("Expected 1 stale row, got %d", len(stale))
	}
	if stale[0].MetricKey != "stale_metric" {
		t.Errorf("Expected stale_metric, got %s", stale[0].MetricKey)
	}
}

func TestStalenessStore_QueryStale_Empty(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	stale, err := s.QueryStale(time.Now())
	if err != nil {
		t.Fatalf("Expected no error for empty DB, got: %v", err)
	}
	if len(stale) != 0 {
		t.Errorf("Expected 0 stale rows, got %d", len(stale))
	}
}

func TestStalenessStore_FlushBatch(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	batch := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
		{MetricKey: "m2", FamilyName: "f2", LabelsJSON: `{}`},
	}

	lastSeen := int64(1000000)
	if err := s.FlushBatch(batch, lastSeen); err != nil {
		t.Fatalf("FlushBatch failed: %v", err)
	}

	if len(db.upserts) != 1 {
		t.Fatalf("Expected 1 upsert call, got %d", len(db.upserts))
	}
	for _, row := range db.upserts[0] {
		if row.LastSeenUnix != lastSeen {
			t.Errorf("Expected LastSeenUnix=%d, got %d", lastSeen, row.LastSeenUnix)
		}
	}

	// Verify rows are stored in mock
	if len(db.rows) != 2 {
		t.Errorf("Expected 2 rows stored, got %d", len(db.rows))
	}
}

func TestStalenessStore_FlushBatch_Upsert(t *testing.T) {
	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			{MetricKey: "m1", FamilyName: "f1", LastSeenUnix: 100},
		},
	}
	s := NewStalenessStore(db, time.Hour)

	// Upsert same key with new timestamp
	batch := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
	}
	if err := s.FlushBatch(batch, 200); err != nil {
		t.Fatalf("FlushBatch failed: %v", err)
	}

	if len(db.rows) != 1 {
		t.Errorf("Expected 1 row (upsert not insert), got %d", len(db.rows))
	}
	if db.rows[0].LastSeenUnix != 200 {
		t.Errorf("Expected LastSeenUnix=200 after upsert, got %d", db.rows[0].LastSeenUnix)
	}
}

func TestStalenessStore_DeleteExpired(t *testing.T) {
	db := &mockStalenessDB{}
	window := time.Hour
	s := NewStalenessStore(db, window)

	cycleStart := time.Unix(2000000, 0)
	s.DeleteExpired(cycleStart)

	// Should wait for async goroutine to finish — but DeleteExpired is sync in StalenessStore.
	// The implementation calls db.DeleteExpiredStaleness synchronously.
	expectedExpire := cycleStart.Unix() - int64(window.Seconds())
	if db.deleted != expectedExpire {
		t.Errorf("Expected expireBefore=%d, got %d", expectedExpire, db.deleted)
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
