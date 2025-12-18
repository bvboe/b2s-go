package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bvboe/b2s-go/pod-scanner/handlers"
	"github.com/bvboe/b2s-go/pod-scanner/runtime"
)

// version is set at build time via ldflags
var version = "dev"

type InfoResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	NodeName  string `json:"node_name"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

// healthHandler returns a simple OK response for health checks
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, "OK"); err != nil {
		log.Printf("Error writing health response: %v", err)
	}
}

// infoHandler returns component information as JSON
func infoHandler(w http.ResponseWriter, r *http.Request) {
	info := InfoResponse{
		Component: "pod-scanner",
		Version:   version,
		NodeName:  os.Getenv("NODE_NAME"),
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("Error encoding info response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize runtime manager for SBOM generation
	runtimeMgr, err := runtime.NewManager()
	if err != nil {
		log.Fatalf("Failed to initialize container runtime: %v", err)
	}
	defer func() {
		if err := runtimeMgr.Close(); err != nil {
			log.Printf("Warning: failed to close runtime manager: %v", err)
		}
	}()

	log.Printf("Using container runtime: %s", runtimeMgr.ActiveRuntime())

	// Register HTTP endpoints
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/sbom/", handlers.SBOMHandler(runtimeMgr))

	log.Printf("pod-scanner v%s starting on port %s (node: %s)", version, port, os.Getenv("NODE_NAME"))
	log.Printf("Endpoints: /health, /info, /sbom/{digest}")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
