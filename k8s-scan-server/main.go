package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// version is set at build time via ldflags
var version = "dev"

// formatConsoleURL creates a console URL, omitting port 80 for cleaner URLs
func formatConsoleURL(host, port string) string {
	if port == "80" {
		return fmt.Sprintf("http://%s/", host)
	}
	return fmt.Sprintf("http://%s:%s/", host, port)
}

type InfoResponse struct {
	Version   string `json:"version"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

type K8sScanServerInfo struct {
	port         string
	webUIEnabled bool
	k8sClient    kubernetes.Interface
	serviceName  string
	servicePort  string
	// Cached values computed at startup and refreshed periodically
	deploymentIP     string
	cachedConsoleURL string
	consoleMu        sync.RWMutex // Protects cachedConsoleURL
	// Database readiness state for grype DB status
	dbReadinessState *corehandlers.DatabaseReadinessState
}

func NewK8sScanServerInfo(port string, webUIEnabled bool, customConsoleURL string, k8sClient kubernetes.Interface, serviceName, servicePort string) *K8sScanServerInfo {
	info := &K8sScanServerInfo{
		port:         port,
		webUIEnabled: webUIEnabled,
		k8sClient:    k8sClient,
		serviceName:  serviceName,
		servicePort:  servicePort,
	}

	// Cache deployment IP (node IP from downward API)
	info.deploymentIP = os.Getenv("NODE_IP")
	if info.deploymentIP == "" {
		log.Printf("Warning: NODE_IP environment variable not set")
	}

	// Cache console URL at startup
	if customConsoleURL != "" {
		info.cachedConsoleURL = customConsoleURL
	} else if webUIEnabled {
		info.cachedConsoleURL = info.detectConsoleURL()
	}

	if info.cachedConsoleURL != "" {
		log.Printf("Console URL: %s", info.cachedConsoleURL)
	}

	return info
}

// StartPeriodicRefresh starts a background goroutine that periodically refreshes
// the console URL. This handles cases where the service configuration changes
// after startup (e.g., LoadBalancer IP becomes available).
// Only call this if auto-detecting the console URL (no custom URL override).
func (k *K8sScanServerInfo) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newURL := k.detectConsoleURL()
				k.consoleMu.Lock()
				if newURL != k.cachedConsoleURL {
					log.Printf("Console URL updated: %s", newURL)
					k.cachedConsoleURL = newURL
				}
				k.consoleMu.Unlock()
			}
		}
	}()
}

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

func (k *K8sScanServerInfo) GetDeploymentName() string {
	// For k8s, deployment name is the cluster name
	return k.GetClusterName()
}

func (k *K8sScanServerInfo) GetDeploymentType() string {
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

// GetDeploymentIP returns the cached deployment IP (node IP).
func (k *K8sScanServerInfo) GetDeploymentIP() string {
	return k.deploymentIP
}

// GetConsoleURL returns the cached console URL.
func (k *K8sScanServerInfo) GetConsoleURL() string {
	k.consoleMu.RLock()
	defer k.consoleMu.RUnlock()
	return k.cachedConsoleURL
}

// SetDBReadinessState sets the database readiness state for grype DB status reporting.
func (k *K8sScanServerInfo) SetDBReadinessState(state *corehandlers.DatabaseReadinessState) {
	k.dbReadinessState = state
}

// GetGrypeDBBuilt returns the grype vulnerability database build timestamp in RFC3339 format.
// Returns empty string if the database status is unavailable.
func (k *K8sScanServerInfo) GetGrypeDBBuilt() string {
	if k.dbReadinessState == nil {
		return ""
	}
	status := k.dbReadinessState.GetStatus()
	if status == nil || status.Built.IsZero() {
		return ""
	}
	return status.Built.Format(time.RFC3339)
}

// detectConsoleURL determines the console URL based on service configuration.
// Called once at startup and cached.
func (k *K8sScanServerInfo) detectConsoleURL() string {
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	// Try to get service information from Kubernetes API
	if k.k8sClient != nil && k.serviceName != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		svc, err := k.k8sClient.CoreV1().Services(namespace).Get(ctx, k.serviceName, metav1.GetOptions{})
		if err != nil {
			log.Printf("Warning: failed to get service %s: %v", k.serviceName, err)
		} else {
			// Determine URL based on service type
			switch svc.Spec.Type {
			case corev1.ServiceTypeLoadBalancer:
				// Use LoadBalancer IP if available
				if len(svc.Status.LoadBalancer.Ingress) > 0 {
					ingress := svc.Status.LoadBalancer.Ingress[0]
					if ingress.IP != "" {
						port := k.servicePort
						if port == "" && len(svc.Spec.Ports) > 0 {
							port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
						}
						return formatConsoleURL(ingress.IP, port)
					}
					if ingress.Hostname != "" {
						port := k.servicePort
						if port == "" && len(svc.Spec.Ports) > 0 {
							port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
						}
						return formatConsoleURL(ingress.Hostname, port)
					}
				}

			case corev1.ServiceTypeNodePort:
				// Use Node IP + NodePort (NodePort is never 80, so always include it)
				if k.deploymentIP != "" && len(svc.Spec.Ports) > 0 {
					nodePort := svc.Spec.Ports[0].NodePort
					return fmt.Sprintf("http://%s:%d/", k.deploymentIP, nodePort)
				}

			case corev1.ServiceTypeClusterIP:
				// Use internal cluster DNS name
				port := k.servicePort
				if port == "" && len(svc.Spec.Ports) > 0 {
					port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
				}
				return formatConsoleURL(fmt.Sprintf("%s.%s.svc.cluster.local", k.serviceName, namespace), port)
			}
		}
	}

	// Fallback: construct internal cluster DNS name
	if k.serviceName != "" {
		port := k.servicePort
		if port == "" {
			port = "80"
		}
		return formatConsoleURL(fmt.Sprintf("%s.%s.svc.cluster.local", k.serviceName, namespace), port)
	}

	return ""
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

	// Configure Grype database location
	// GRYPE_DB_PATH allows storing the grype database separately from the main data
	// This is important for NFS deployments where grype's in-place database updates
	// can fail due to NFS "silly rename" behavior when files are replaced while open
	grypeDBPath := os.Getenv("GRYPE_DB_PATH")
	if grypeDBPath == "" {
		// Default: use the same directory as the main database
		grypeDBPath = filepath.Dir(dbPath)
	}
	grypeCfg := grype.Config{
		DBRootDir: grypeDBPath,
	}
	log.Printf("Grype database path: %s/grype/", grypeDBPath)

	// Initialize database readiness state
	dbReadinessState := corehandlers.NewDatabaseReadinessState(grypeCfg)

	// Initialize vulnerability database at startup (before accepting scans)
	log.Printf("Initializing vulnerability database (this may take a few minutes on first run)...")
	dbStatus, err := grype.InitializeDatabase(grypeCfg)
	if err != nil {
		// Log but don't fail - the scan queue will retry on each scan
		log.Printf("Warning: Failed to initialize vulnerability database: %v", err)
		log.Printf("Scans will attempt to download the database on first use")
		dbReadinessState.SetReady(dbStatus)
	} else {
		log.Printf("Vulnerability database ready: schema=%s, built=%v", dbStatus.SchemaVersion, dbStatus.Built)
		dbReadinessState.SetReady(dbStatus)
	}

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
	var sched *scheduler.Scheduler
	if cfg.JobsEnabled {
		log.Println("Initializing scheduled jobs...")
		sched = scheduler.New()

		// Add rescan database job - uses grype's native update mechanism
		if cfg.JobsRescanDatabaseEnabled {
			dbUpdater, err := vulndb.NewDatabaseUpdater(grypeCfg.DBRootDir)
			if err != nil {
				log.Printf("Warning: failed to create database updater: %v", err)
			} else {
				rescanJob := jobs.NewRescanDatabaseJob(dbUpdater, db, scanQueue)
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
				log.Printf("Scheduled rescan-database job (interval: %v, timeout: %v)", cfg.JobsRescanDatabaseInterval, cfg.JobsRescanDatabaseTimeout)
			}
		}

		// Add cleanup orphaned images job
		if cfg.JobsCleanupEnabled {
			cleanupJob := jobs.NewCleanupOrphanedImagesJob(db)
			if err := sched.AddJob(
				cleanupJob,
				scheduler.NewIntervalSchedule(cfg.JobsCleanupInterval),
				scheduler.JobConfig{
					Enabled: true,
					Timeout: cfg.JobsCleanupTimeout,
				},
			); err != nil {
				log.Fatalf("Failed to add cleanup job: %v", err)
			}
			log.Printf("Scheduled cleanup-orphaned-images job (interval: %v, timeout: %v)", cfg.JobsCleanupInterval, cfg.JobsCleanupTimeout)
		}

		// Start scheduler
		if err := sched.Start(ctx); err != nil {
			log.Fatalf("Failed to start scheduler: %v", err)
		}
		log.Println("Scheduler started")
	}

	// Setup HTTP server
	// Get console URL configuration from environment (can be overridden via Helm)
	consoleURL := os.Getenv("CONSOLE_URL")
	serviceName := os.Getenv("SERVICE_NAME")
	servicePort := os.Getenv("SERVICE_PORT")
	if servicePort == "" {
		servicePort = "80" // Default service port
	}

	infoProvider := NewK8sScanServerInfo(port, cfg.WebUIEnabled, consoleURL, clientset, serviceName, servicePort)

	// Connect database readiness state for grype DB status reporting in metrics
	infoProvider.SetDBReadinessState(dbReadinessState)

	// Start periodic refresh for console URL detection (only if auto-detecting)
	// This handles LoadBalancer IPs that aren't available immediately at startup
	if consoleURL == "" && cfg.WebUIEnabled {
		infoProvider.StartPeriodicRefresh(ctx, 5*time.Minute)
	}

	mux := http.NewServeMux()

	// Register standard handlers
	corehandlers.RegisterHandlers(mux, infoProvider)

	// Register database readiness handlers (/ready, /api/db/status, /api/debug/db/reinit)
	corehandlers.RegisterDatabaseReadinessHandlers(mux, dbReadinessState)

	// Register database handlers with SBOM routing override
	// The k8s-scan-server routes SBOM requests to pod-scanner on the appropriate node
	dbHandlerOverrides := &corehandlers.HandlerOverrides{
		SBOMHandler: handlers.SBOMDownloadWithRoutingHandler(db, clientset, podScannerClient),
	}
	corehandlers.RegisterDatabaseHandlers(mux, db, dbHandlerOverrides)

	// Register static file handlers (web UI) only if enabled
	if cfg.WebUIEnabled {
		corehandlers.RegisterStaticHandlers(mux)
	}

	// Register debug handlers if debug mode is enabled
	corehandlers.RegisterDebugHandlers(mux, db, debugConfig, scanQueue)

	// Register jobs debug handlers for listing, triggering, and viewing execution history
	corehandlers.RegisterJobsHandlersWithDB(mux, sched, db)

	// Create collector config for metrics
	collectorConfig := metrics.CollectorConfig{
		DeploymentEnabled:             cfg.MetricsDeploymentEnabled,
		ScannedInstancesEnabled:       cfg.MetricsScannedInstancesEnabled,
		VulnerabilitiesEnabled:        cfg.MetricsVulnerabilitiesEnabled,
		VulnerabilityExploitedEnabled: cfg.MetricsVulnerabilityExploitedEnabled,
		VulnerabilityRiskEnabled:      cfg.MetricsVulnerabilityRiskEnabled,
		ImageScanStatusEnabled:        cfg.MetricsImageScanStatusEnabled,
	}

	// Create metric tracker for staleness detection (shared between /metrics and OTEL)
	metricTracker := metrics.NewMetricTracker(metrics.MetricTrackerConfig{
		StalenessWindow: cfg.MetricsStalenessWindow,
		Store:           db,
		StorageKey:      "metrics",
	})
	log.Printf("Metric staleness tracking enabled (window: %v)", cfg.MetricsStalenessWindow)

	// Register Prometheus metrics endpoint with staleness tracking
	metrics.RegisterMetricsHandlerWithTracker(mux, infoProvider, deploymentUUID.String(), db, collectorConfig, metricTracker)

	// Initialize OpenTelemetry metrics exporter if enabled
	var otelExporter *metrics.OTELExporter
	if cfg.OTELMetricsEnabled {
		log.Printf("Initializing OpenTelemetry metrics exporter (endpoint: %s, protocol: %s, interval: %v)",
			cfg.OTELMetricsEndpoint, cfg.OTELMetricsProtocol, cfg.OTELMetricsPushInterval)

		otelConfig := metrics.OTELConfig{
			Endpoint:     cfg.OTELMetricsEndpoint,
			Protocol:     metrics.OTELProtocol(cfg.OTELMetricsProtocol),
			PushInterval: cfg.OTELMetricsPushInterval,
			Insecure:     cfg.OTELMetricsInsecure,
		}

		var err error
		otelExporter, err = metrics.NewOTELExporter(ctx, infoProvider, deploymentUUID.String(), db, collectorConfig, otelConfig)
		if err != nil {
			log.Printf("Warning: Failed to initialize OTEL exporter: %v (continuing without OTEL)", err)
		} else {
			// Set the same tracker for consistent staleness detection
			otelExporter.SetTracker(metricTracker)
			otelExporter.Start()
			log.Println("OpenTelemetry metrics exporter started")
		}
	}

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

	// Shutdown OTEL exporter if running
	if otelExporter != nil {
		log.Println("Shutting down OpenTelemetry exporter...")
		if err := otelExporter.Shutdown(); err != nil {
			log.Printf("Error shutting down OTEL exporter: %v", err)
		}
	}

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("k8s-scan-server stopped")
}
