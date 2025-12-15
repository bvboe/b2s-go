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
	Version   string `json:"version"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

type K8sScanServerInfo struct{}

func (k *K8sScanServerInfo) GetInfo() interface{} {
	return InfoResponse{
		Version:   version,
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	infoProvider := &K8sScanServerInfo{}

	// Register standard scanner endpoints
	handlers.RegisterDefaultHandlers(infoProvider)

	log.Printf("k8s-scan-server v%s starting on port %s", version, port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
