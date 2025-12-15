package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// InfoProvider is an interface for components to provide their specific information
type InfoProvider interface {
	GetInfo() interface{}
}

// HealthHandler returns a simple OK response for health checks
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, "OK"); err != nil {
		log.Printf("Error writing health response: %v", err)
	}
}

// InfoHandler creates an HTTP handler for the /info endpoint
// It accepts an InfoProvider to get component-specific information
func InfoHandler(provider InfoProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := provider.GetInfo()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			log.Printf("Error encoding info response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// RegisterHandlers registers the standard scanner endpoints (/health and /info) on the provided mux
func RegisterHandlers(mux *http.ServeMux, provider InfoProvider) {
	mux.HandleFunc("/health", HealthHandler)
	mux.HandleFunc("/info", InfoHandler(provider))
}

// RegisterDefaultHandlers registers the standard scanner endpoints (/health and /info) on the default mux
func RegisterDefaultHandlers(provider InfoProvider) {
	http.HandleFunc("/health", HealthHandler)
	http.HandleFunc("/info", InfoHandler(provider))
}
