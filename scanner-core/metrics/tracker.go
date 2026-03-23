package metrics

import (
	"sort"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// DefaultStalenessWindow is the default duration after which metrics are considered stale
const DefaultStalenessWindow = 60 * time.Minute

// defaultBatchSize is the number of staleness rows flushed to the DB per batch during streaming.
// At ~200 bytes/row this keeps working memory at ~200KB per batch regardless of total row count.
const defaultBatchSize = 1000

// StalenessDB is the subset of StreamingProvider needed for staleness operations.
// This is a separate interface so StalenessStore can be unit-tested with a mock.
type StalenessDB interface {
	QueryStaleness(cycleStart, windowSecs int64) ([]database.StalenessRow, error)
	UpsertStaleness(batch []database.StalenessRow) error
	DeleteExpiredStaleness(expireBefore int64) error
}

// StalenessStore tracks per-metric-point staleness using the metric_staleness DB table.
// It replaces the old MetricTracker (which stored a JSON blob in app_state).
//
// Staleness behavior (unchanged from MetricTracker):
// 1. A metric present in the current collection cycle has its last_seen_unix updated.
// 2. A metric that disappears has NaN emitted for up to StalenessWindow duration.
// 3. After StalenessWindow expires, the row is deleted (metric disappears completely).
type StalenessStore struct {
	db              StalenessDB
	stalenessWindow time.Duration
	batchSize       int
}

// NewStalenessStore creates a StalenessStore backed by the given database.
func NewStalenessStore(db StalenessDB, stalenessWindow time.Duration) *StalenessStore {
	if stalenessWindow == 0 {
		stalenessWindow = DefaultStalenessWindow
	}
	return &StalenessStore{
		db:              db,
		stalenessWindow: stalenessWindow,
		batchSize:       defaultBatchSize,
	}
}

// QueryStale returns metric rows that were seen in a previous cycle but not in the
// current one (i.e., they disappeared). The result is small in a stable cluster —
// safe to load into memory for use when writing NaN lines to the HTTP response.
func (s *StalenessStore) QueryStale(cycleStart time.Time) ([]database.StalenessRow, error) {
	return s.db.QueryStaleness(cycleStart.Unix(), int64(s.stalenessWindow.Seconds()))
}

// FlushBatch upserts a batch of staleness rows to the database, setting lastSeenUnix on all rows.
func (s *StalenessStore) FlushBatch(batch []database.StalenessRow, lastSeenUnix int64) error {
	for i := range batch {
		batch[i].LastSeenUnix = lastSeenUnix
	}
	return s.db.UpsertStaleness(batch)
}

// FlushAll upserts all staleness rows to the database in batches.
// Intended to be called after the HTTP response is flushed, so DB writes don't block the client.
func (s *StalenessStore) FlushAll(rows []database.StalenessRow, cycleStart time.Time) {
	if len(rows) == 0 {
		return
	}
	cycleStartUnix := cycleStart.Unix()
	for i := range rows {
		rows[i].LastSeenUnix = cycleStartUnix
	}
	for i := 0; i < len(rows); i += s.batchSize {
		end := i + s.batchSize
		if end > len(rows) {
			end = len(rows)
		}
		if err := s.db.UpsertStaleness(rows[i:end]); err != nil {
			log.Warn("failed to flush staleness batch", "error", err)
		}
	}
}

// DeleteExpired removes staleness rows that are past the staleness window.
// Intended to be called asynchronously after the HTTP response is flushed.
func (s *StalenessStore) DeleteExpired(cycleStart time.Time) {
	expireBefore := cycleStart.Unix() - int64(s.stalenessWindow.Seconds())
	if err := s.db.DeleteExpiredStaleness(expireBefore); err != nil {
		log.Warn("failed to delete expired staleness entries", "error", err)
	}
}

// BatchSize returns the configured batch size (exposed for tests).
func (s *StalenessStore) BatchSize() int {
	return s.batchSize
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
