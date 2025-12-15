package main

import (
	"log"
	"net/http"
	"os"

	"github.com/bvboe/b2s-go/scanner-core/handlers"
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

type PodScannerInfo struct{}

func (p *PodScannerInfo) GetInfo() interface{} {
	return InfoResponse{
		Component: "pod-scanner",
		Version:   version,
		NodeName:  os.Getenv("NODE_NAME"),
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	infoProvider := &PodScannerInfo{}

	// Register standard scanner endpoints
	handlers.RegisterDefaultHandlers(infoProvider)

	log.Printf("pod-scanner v%s starting on port %s (node: %s)", version, port, os.Getenv("NODE_NAME"))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
