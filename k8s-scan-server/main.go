package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/k8s-scan-server/handlers"
	"github.com/bvboe/b2s-go/k8s-scan-server/k8s"
	"github.com/bvboe/b2s-go/k8s-scan-server/podscanner"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	corehandlers "github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	// SQLite driver is registered by Grype's dependencies

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

	log.Printf("k8s-scan-server v%s starting", version)

	// Create Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error creating Kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	// Create container manager
	manager := containers.NewManager()

	// Initialize database
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/bjorn2scan/containers.db"
	}

	// Initialize debug configuration
	debugEnabled := os.Getenv("DEBUG_ENABLED")
	debugConfig := debug.NewDebugConfig(debugEnabled == "true")
	if debugConfig.IsEnabled() {
		log.Println("Debug mode ENABLED - /debug endpoints available")
	}

	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Connect database to manager
	manager.SetDatabase(db)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Perform initial sync
	if err := k8s.SyncInitialPods(ctx, clientset, manager); err != nil {
		log.Fatalf("Error performing initial pod sync: %v", err)
	}

	// Start pod watcher in background
	go k8s.WatchPods(ctx, clientset, manager)

	// Create pod-scanner client for SBOM routing
	podScannerClient := podscanner.NewClient()

	// Create SBOM retriever function that uses pod-scanner
	sbomRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return podScannerClient.GetSBOMFromNode(ctx, clientset, nodeName, image.Digest)
	}

	// Configure Grype to use persistent storage
	// Get the data directory from the database path
	dataDir := filepath.Dir(dbPath)
	grypeCfg := grype.Config{
		DBRootDir: dataDir, // Store Grype database in same persistent volume as SQLite database
	}
	log.Printf("Grype will use persistent storage at: %s/grype/", dataDir)

	// Create scan queue for automatic SBOM generation and vulnerability scanning
	scanQueue := scanning.NewJobQueue(db, sbomRetriever, grypeCfg)
	defer scanQueue.Shutdown()

	// Connect scan queue to manager
	manager.SetScanQueue(scanQueue)

	// Setup HTTP server
	infoProvider := &K8sScanServerInfo{}
	mux := http.NewServeMux()

	// Register standard handlers
	corehandlers.RegisterHandlers(mux, infoProvider)

	// Register database handlers with SBOM routing override
	// The k8s-scan-server routes SBOM requests to pod-scanner on the appropriate node
	dbHandlerOverrides := &corehandlers.HandlerOverrides{
		SBOMHandler: handlers.SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient),
	}
	corehandlers.RegisterDatabaseHandlers(mux, db, dbHandlerOverrides)

	// Register static file handlers (web UI)
	corehandlers.RegisterStaticHandlers(mux)

	// Register debug handlers if debug mode is enabled
	corehandlers.RegisterDebugHandlers(mux, db, debugConfig, scanQueue)

	// Wrap with logging middleware if debug enabled
	var handler http.Handler = mux
	if debugConfig.IsEnabled() {
		handler = debug.LoggingMiddleware(debugConfig, mux)
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("k8s-scan-server listening on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, shutting down gracefully...")

	// Cancel context to stop pod watcher
	cancel()

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("k8s-scan-server stopped")
}
