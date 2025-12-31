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
	scannerconfig "github.com/bvboe/b2s-go/scanner-core/config"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/deployment"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	corehandlers "github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/jobs"
	"github.com/bvboe/b2s-go/scanner-core/metrics"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/scheduler"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
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

func (k *K8sScanServerInfo) GetClusterName() string {
	// Try to get cluster name from environment variable first
	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName != "" {
		return clusterName
	}

	// Fall back to namespace if available
	namespace := os.Getenv("NAMESPACE")
	if namespace != "" {
		return namespace
	}

	// Final fallback
	return "kubernetes"
}

func (k *K8sScanServerInfo) GetVersion() string {
	return version
}

func (k *K8sScanServerInfo) GetScanContainers() bool {
	// Default to true, can be disabled via env var
	scanContainers := os.Getenv("SCAN_CONTAINERS")
	if scanContainers == "false" || scanContainers == "0" {
		return false
	}
	return true
}

func (k *K8sScanServerInfo) GetScanNodes() bool {
	// Default to false, can be enabled via env var
	scanNodes := os.Getenv("SCAN_NODES")
	if scanNodes == "true" || scanNodes == "1" {
		return true
	}
	return false
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
		dbPath = "/var/lib/bjorn2scan/data/containers.db"
	}

	// Initialize debug configuration
	debugEnabled := os.Getenv("DEBUG_ENABLED")
	debugConfig := debug.NewDebugConfig(debugEnabled == "true")
	if debugConfig.IsEnabled() {
		log.Println("Debug mode ENABLED - /debug endpoints available")
	}

	// Initialize database (will auto-delete and recreate if corrupted)
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Initialize deployment UUID
	dbDir := filepath.Dir(dbPath)
	deploymentUUID, err := deployment.NewUUID(dbDir)
	if err != nil {
		log.Fatalf("Failed to initialize deployment UUID: %v", err)
	}
	log.Printf("Deployment UUID: %s", deploymentUUID)

	// Load configuration with environment variable overrides from Helm values
	cfg, err := scannerconfig.LoadConfig("")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

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
	// Using default queue config (unbounded queue with single worker)
	queueConfig := scanning.QueueConfig{
		MaxDepth:     0, // Unbounded
		FullBehavior: scanning.QueueFullDrop,
	}
	scanQueue := scanning.NewJobQueue(db, sbomRetriever, grypeCfg, queueConfig)
	defer scanQueue.Shutdown()

	// Connect scan queue to manager
	manager.SetScanQueue(scanQueue)

	// Initialize scheduler for periodic jobs
	if cfg.JobsEnabled && cfg.JobsRescanDatabaseEnabled {
		log.Println("Initializing scheduled jobs...")
		sched := scheduler.New()

		// Add rescan database job
		feedChecker, err := vulndb.NewFeedChecker(grypeCfg.DBRootDir)
		if err != nil {
			log.Printf("Warning: failed to create feed checker: %v", err)
		} else {
			rescanJob := jobs.NewRescanDatabaseJob(feedChecker, db, scanQueue)
			if err := sched.AddJob(
				rescanJob,
				scheduler.NewIntervalSchedule(cfg.JobsRescanDatabaseInterval),
				scheduler.JobConfig{
					Enabled: true,
					Timeout: cfg.JobsRescanDatabaseTimeout,
				},
			); err != nil {
				log.Fatalf("Failed to add rescan database job: %v", err)
			}
			log.Printf("Scheduled rescan database job (interval: %v, timeout: %v)", cfg.JobsRescanDatabaseInterval, cfg.JobsRescanDatabaseTimeout)

			// Start scheduler
			if err := sched.Start(ctx); err != nil {
				log.Fatalf("Failed to start scheduler: %v", err)
			}
			log.Println("Scheduler started")
		}
	}

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

	// Register Prometheus metrics endpoint
	metrics.RegisterMetricsHandler(mux, db, infoProvider)

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
