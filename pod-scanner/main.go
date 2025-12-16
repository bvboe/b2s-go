package main

import (
	"log"
	"net/http"
	"os"

	corehandlers "github.com/bvboe/b2s-go/scanner-core/handlers"
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

	infoProvider := &PodScannerInfo{}

	// Register standard scanner endpoints (health, info)
	corehandlers.RegisterDefaultHandlers(infoProvider)

	// Register SBOM generation endpoint
	http.HandleFunc("/sbom/", handlers.SBOMHandler(runtimeMgr))

	log.Printf("pod-scanner v%s starting on port %s (node: %s)", version, port, os.Getenv("NODE_NAME"))
	log.Printf("Endpoints: /health, /info, /sbom/{digest}")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
