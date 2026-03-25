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
	mu        sync.Mutex
	rows      []database.StalenessRow
	inserts   []database.StalenessRow
	staled    []string
	activated []string
	deleted   int64
	err       error
}

func (m *mockStalenessDB) QueryStaleness(cycleStart int64) ([]database.StalenessRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var stale []database.StalenessRow
	for _, r := range m.rows {
		if r.ExpiresAtUnix != nil && *r.ExpiresAtUnix > cycleStart {
			stale = append(stale, r)
		}
	}
	return stale, nil
}

func (m *mockStalenessDB) LoadStalenessState(cycleStart int64) ([]database.StalenessRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var result []database.StalenessRow
	for _, r := range m.rows {
		if r.ExpiresAtUnix == nil || *r.ExpiresAtUnix > cycleStart {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockStalenessDB) InsertNewMetrics(batch []database.StalenessRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	for _, newRow := range batch {
		found := false
		for _, r := range m.rows {
			if r.MetricKey == newRow.MetricKey {
				found = true
				break
			}
		}
		if !found {
			m.rows = append(m.rows, newRow)
			m.inserts = append(m.inserts, newRow)
		}
	}
	return nil
}

func (m *mockStalenessDB) MarkMetricsStale(keys []string, expiresAtUnix int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.staled = append(m.staled, keys...)
	for _, key := range keys {
		for i, r := range m.rows {
			if r.MetricKey == key {
				v := expiresAtUnix
				m.rows[i].ExpiresAtUnix = &v
			}
		}
	}
	return nil
}

func (m *mockStalenessDB) MarkMetricsActive(keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.activated = append(m.activated, keys...)
	for _, key := range keys {
		for i, r := range m.rows {
			if r.MetricKey == key {
				m.rows[i].ExpiresAtUnix = nil
			}
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
		if r.ExpiresAtUnix == nil || *r.ExpiresAtUnix >= expireBefore {
			kept = append(kept, r)
		}
	}
	m.rows = kept
	return nil
}

func ptr64(v int64) *int64 { return &v }

// ── StalenessStore construction ──────────────────────────────────────────────

func TestNewStalenessStore_Defaults(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, 0) // zero → DefaultStalenessWindow

	if s.StalenessWindow() != DefaultStalenessWindow {
		t.Errorf("Expected default window %v, got %v", DefaultStalenessWindow, s.StalenessWindow())
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

// ── QueryStale ───────────────────────────────────────────────────────────────

func TestStalenessStore_QueryStale(t *testing.T) {
	cycleStart := time.Unix(2000000, 0)
	futureExpiry := cycleStart.Unix() + 3600 // expires 1 hour after cycleStart
	pastExpiry := cycleStart.Unix() - 1      // already expired

	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			// Stale, not yet expired — should be returned
			{MetricKey: "stale_metric", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: ptr64(futureExpiry)},
			// Already expired — should NOT be returned
			{MetricKey: "expired_metric", FamilyName: "f2", LabelsJSON: `{}`, ExpiresAtUnix: ptr64(pastExpiry)},
			// Active (nil expiry) — should NOT be returned
			{MetricKey: "active_metric", FamilyName: "f3", LabelsJSON: `{}`, ExpiresAtUnix: nil},
		},
	}

	s := NewStalenessStore(db, time.Hour)
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

// ── ApplyDiff ────────────────────────────────────────────────────────────────

func TestApplyDiff_NewMetrics(t *testing.T) {
	db := &mockStalenessDB{} // empty DB
	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.inserts) != 2 {
		t.Errorf("Expected 2 inserts for new metrics, got %d", len(db.inserts))
	}
	if len(db.staled) != 0 {
		t.Errorf("Expected 0 stale marks, got %d", len(db.staled))
	}
	if len(db.activated) != 0 {
		t.Errorf("Expected 0 activations, got %d", len(db.activated))
	}
}

func TestApplyDiff_StableCluster_NoWrites(t *testing.T) {
	// Active rows in DB that match current cycle exactly — zero writes.
	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: nil},
			{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: nil},
		},
	}
	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.inserts) != 0 {
		t.Errorf("Expected 0 inserts for stable cluster, got %d", len(db.inserts))
	}
	if len(db.staled) != 0 {
		t.Errorf("Expected 0 stale marks for stable cluster, got %d", len(db.staled))
	}
	if len(db.activated) != 0 {
		t.Errorf("Expected 0 activations for stable cluster, got %d", len(db.activated))
	}
}

func TestApplyDiff_DisappearedMetric(t *testing.T) {
	// m1 was active, not seen this cycle → mark stale
	// m2 was active, still present → no write
	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: nil},
			{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: nil},
		},
	}
	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	cycleStart := time.Unix(2000000, 0)
	if err := s.ApplyDiff(current, cycleStart); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.staled) != 1 || db.staled[0] != "m1" {
		t.Errorf("Expected m1 to be marked stale, got %v", db.staled)
	}
	// Verify expiry is set correctly
	for _, r := range db.rows {
		if r.MetricKey == "m1" {
			if r.ExpiresAtUnix == nil {
				t.Error("Expected m1 to have expires_at_unix set")
			} else {
				expected := cycleStart.Unix() + int64(time.Hour.Seconds())
				if *r.ExpiresAtUnix != expected {
					t.Errorf("Expected expires_at_unix=%d, got %d", expected, *r.ExpiresAtUnix)
				}
			}
		}
	}
}

func TestApplyDiff_ReappearedMetric(t *testing.T) {
	// m1 was stale (has expires_at_unix), reappears this cycle → mark active
	futureExpiry := time.Now().Add(30 * time.Minute).Unix()
	db := &mockStalenessDB{
		rows: []database.StalenessRow{
			{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`, ExpiresAtUnix: ptr64(futureExpiry)},
		},
	}
	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.activated) != 1 || db.activated[0] != "m1" {
		t.Errorf("Expected m1 to be reactivated, got %v", db.activated)
	}
	if len(db.inserts) != 0 {
		t.Errorf("Expected 0 inserts (was already tracked), got %d", len(db.inserts))
	}
}

// ── DeleteExpired ─────────────────────────────────────────────────────────────

func TestStalenessStore_DeleteExpired(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	cycleStart := time.Unix(2000000, 0)
	s.DeleteExpired(cycleStart)

	if db.deleted != cycleStart.Unix() {
		t.Errorf("Expected expireBefore=%d, got %d", cycleStart.Unix(), db.deleted)
	}
}

// ── generateMetricKey ─────────────────────────────────────────────────────────

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
