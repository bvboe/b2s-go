package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

const version = "0.1.0"

type InfoResponse struct {
	Version   string `json:"version"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	info := InfoResponse{
		Version:   version,
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/info", infoHandler)

	log.Printf("k8s-scan-server v%s starting on port %s", version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
