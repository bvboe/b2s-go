package metrics

import (
	"fmt"
	"sort"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// DefaultStalenessWindow is the default duration after which metrics are considered stale
const DefaultStalenessWindow = 60 * time.Minute

// StalenessDB is the subset of StreamingProvider needed for staleness operations.
// This is a separate interface so StalenessStore can be unit-tested with a mock.
type StalenessDB interface {
	QueryStaleness(cycleStart int64) ([]database.StalenessRow, error)
	LoadStalenessState(cycleStart int64) ([]database.StalenessRow, error)
	InsertNewMetrics(batch []database.StalenessRow) error
	MarkMetricsStale(keys []string, expiresAtUnix int64) error
	MarkMetricsActive(keys []string) error
	DeleteExpiredStaleness(expireBefore int64) error
}

// StalenessStore tracks per-metric-point staleness using the metric_staleness DB table.
//
// Staleness behavior:
// 1. A metric seen in the current cycle that is new gets one INSERT (active, NULL expiry).
// 2. A metric that disappears gets one UPDATE to set expires_at_unix (stale with deadline).
// 3. During the stale grace period the metric emits NaN; after it expires the row is deleted.
// 4. A stale metric that reappears gets one UPDATE to clear expires_at_unix.
// 5. Active metrics that remain active require zero DB writes per cycle.
type StalenessStore struct {
	db              StalenessDB
	stalenessWindow time.Duration
}

// NewStalenessStore creates a StalenessStore backed by the given database.
func NewStalenessStore(db StalenessDB, stalenessWindow time.Duration) *StalenessStore {
	if stalenessWindow == 0 {
		stalenessWindow = DefaultStalenessWindow
	}
	return &StalenessStore{
		db:              db,
		stalenessWindow: stalenessWindow,
	}
}

// QueryStale returns metric rows in the stale grace period (disappeared but not yet expired).
// These are emitted as NaN in the current collection cycle.
func (s *StalenessStore) QueryStale(cycleStart time.Time) ([]database.StalenessRow, error) {
	return s.db.QueryStaleness(cycleStart.Unix())
}

// ApplyDiff compares currentRows (all metric series seen this cycle) against the DB state
// and writes only what changed:
//   - New series (not previously tracked) → INSERT
//   - Disappeared series (tracked as active, not seen this cycle) → mark stale
//   - Reappeared series (tracked as stale, seen this cycle) → clear stale marker
//   - Stable series (tracked as active, seen this cycle) → no write
//
// In a stable cluster this is one read and zero writes.
func (s *StalenessStore) ApplyDiff(currentRows []database.StalenessRow, cycleStart time.Time) error {
	dbRows, err := s.db.LoadStalenessState(cycleStart.Unix())
	if err != nil {
		return fmt.Errorf("failed to load staleness state: %w", err)
	}

	activeInDB := make(map[string]bool, len(dbRows))
	staleInDB := make(map[string]bool)
	for _, r := range dbRows {
		if r.ExpiresAtUnix == nil {
			activeInDB[r.MetricKey] = true
		} else {
			staleInDB[r.MetricKey] = true
		}
	}

	currentKeys := make(map[string]bool, len(currentRows))
	var toInsert []database.StalenessRow
	var toActivate []string
	for _, r := range currentRows {
		currentKeys[r.MetricKey] = true
		switch {
		case activeInDB[r.MetricKey]:
			// Already active — no write needed
		case staleInDB[r.MetricKey]:
			// Was stale, now back — clear stale marker
			toActivate = append(toActivate, r.MetricKey)
		default:
			// Brand new — insert
			toInsert = append(toInsert, r)
		}
	}

	expiresAt := cycleStart.Unix() + int64(s.stalenessWindow.Seconds())
	var toStale []string
	for key := range activeInDB {
		if !currentKeys[key] {
			toStale = append(toStale, key)
		}
	}

	if len(toInsert) > 0 {
		if err := s.db.InsertNewMetrics(toInsert); err != nil {
			return fmt.Errorf("failed to insert new metrics: %w", err)
		}
	}
	if len(toActivate) > 0 {
		if err := s.db.MarkMetricsActive(toActivate); err != nil {
			return fmt.Errorf("failed to reactivate metrics: %w", err)
		}
	}
	if len(toStale) > 0 {
		if err := s.db.MarkMetricsStale(toStale, expiresAt); err != nil {
			return fmt.Errorf("failed to mark metrics stale: %w", err)
		}
	}
	return nil
}

// DeleteExpired removes staleness rows whose expiry has passed.
// Intended to be called asynchronously after each collection cycle.
func (s *StalenessStore) DeleteExpired(cycleStart time.Time) {
	if err := s.db.DeleteExpiredStaleness(cycleStart.Unix()); err != nil {
		log.Warn("failed to delete expired staleness entries", "error", err)
	}
}

// StalenessWindow returns the configured staleness window.
func (s *StalenessStore) StalenessWindow() time.Duration {
	return s.stalenessWindow
}

// generateMetricKey creates a unique key for a metric based on its family name and labels.
// Key format: "familyName|label1=value1|label2=value2|..." (labels sorted alphabetically).
// This key is used as the PRIMARY KEY in the metric_staleness table.
func generateMetricKey(familyName string, labels map[string]string) string {
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
