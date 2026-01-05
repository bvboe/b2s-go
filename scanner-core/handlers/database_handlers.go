package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/bvboe/b2s-go/scanner-core/grype"
)

// DatabaseReadinessState tracks the current database readiness
type DatabaseReadinessState struct {
	mu       sync.RWMutex
	ready    bool
	status   *grype.DatabaseStatus
	grypeCfg grype.Config
}

// NewDatabaseReadinessState creates a new readiness state tracker
func NewDatabaseReadinessState(cfg grype.Config) *DatabaseReadinessState {
	return &DatabaseReadinessState{
		grypeCfg: cfg,
		ready:    false,
	}
}

// SetReady marks the database as ready with the given status
func (d *DatabaseReadinessState) SetReady(status *grype.DatabaseStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ready = status != nil && status.Available
	d.status = status
}

// IsReady returns whether the database is ready
func (d *DatabaseReadinessState) IsReady() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ready
}

// GetStatus returns the current database status
func (d *DatabaseReadinessState) GetStatus() *grype.DatabaseStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.status != nil {
		// Return a copy
		statusCopy := *d.status
		return &statusCopy
	}
	return nil
}

// ReadinessHandler returns a handler that checks if the database is ready
// Returns 200 OK if ready, 503 Service Unavailable if not
func ReadinessHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if state.IsReady() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}

		status := state.GetStatus()
		w.WriteHeader(http.StatusServiceUnavailable)
		if status != nil && status.Error != "" {
			_, _ = w.Write([]byte("not ready: " + status.Error))
		} else {
			_, _ = w.Write([]byte("not ready: database not initialized"))
		}
	}
}

// DatabaseStatusHandler returns the current database status as JSON
func DatabaseStatusHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := state.GetStatus()
		if status == nil {
			status = &grype.DatabaseStatus{
				Available: false,
				Error:     "database not initialized",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Printf("Error encoding database status: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// DatabaseReinitHandler triggers a database re-initialization (for testing)
// POST /api/debug/db/reinit - deletes and re-downloads the database
func DatabaseReinitHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		log.Printf("[db-reinit] Database re-initialization requested")

		// Mark as not ready during re-init
		state.SetReady(&grype.DatabaseStatus{Available: false, Error: "re-initializing"})

		// Delete existing database
		if err := grype.DeleteDatabase(state.grypeCfg); err != nil {
			log.Printf("[db-reinit] Failed to delete database: %v", err)
			state.SetReady(&grype.DatabaseStatus{Available: false, Error: err.Error()})
			http.Error(w, "Failed to delete database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-initialize (download fresh)
		status, err := grype.InitializeDatabase(state.grypeCfg)
		if err != nil {
			log.Printf("[db-reinit] Failed to re-initialize database: %v", err)
			state.SetReady(status)
			http.Error(w, "Failed to initialize database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		state.SetReady(status)
		log.Printf("[db-reinit] Database re-initialized successfully")

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
	}
}

// RegisterDatabaseReadinessHandlers registers the database readiness endpoints
func RegisterDatabaseReadinessHandlers(mux *http.ServeMux, state *DatabaseReadinessState) {
	mux.HandleFunc("/ready", ReadinessHandler(state))
	mux.HandleFunc("/api/db/status", DatabaseStatusHandler(state))
	mux.HandleFunc("/api/debug/db/reinit", DatabaseReinitHandler(state))
}
