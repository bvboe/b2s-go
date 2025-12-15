package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

// DatabaseProvider defines the interface for querying database contents
type DatabaseProvider interface {
	GetAllInstances() (interface{}, error)
	GetAllImages() (interface{}, error)
}

// DatabaseInstancesHandler creates an HTTP handler for /containers/instances endpoint
func DatabaseInstancesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instances, err := provider.GetAllInstances()
		if err != nil {
			log.Printf("Error querying instances: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(instances); err != nil {
			log.Printf("Error encoding instances response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// DatabaseImagesHandler creates an HTTP handler for /containers/images endpoint
func DatabaseImagesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		images, err := provider.GetAllImages()
		if err != nil {
			log.Printf("Error querying images: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(images); err != nil {
			log.Printf("Error encoding images response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// RegisterDatabaseHandlers registers database query endpoints on the provided mux
func RegisterDatabaseHandlers(mux *http.ServeMux, provider DatabaseProvider) {
	mux.HandleFunc("/containers/instances", DatabaseInstancesHandler(provider))
	mux.HandleFunc("/containers/images", DatabaseImagesHandler(provider))
}
