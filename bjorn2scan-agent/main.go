package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/bjorn2scan-agent/docker"
	"github.com/bvboe/b2s-go/bjorn2scan-agent/syft"
	"github.com/bvboe/b2s-go/bjorn2scan-agent/updater"
	"github.com/bvboe/b2s-go/scanner-core/config"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/deployment"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/jobs"
	"github.com/bvboe/b2s-go/scanner-core/metrics"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/scheduler"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
)

// version is set at build time via ldflags
var version = "dev"

type InfoResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type AgentInfo struct {
	port         string
	webUIEnabled bool
	// Cached values computed at startup
	deploymentIP string
	consoleURL   string
	// Grype database status getter (returns RFC3339 timestamp or empty string)
	grypeDBStatusGetter func() string
}

func NewAgentInfo(port string, webUIEnabled bool) *AgentInfo {
	info := &AgentInfo{
		port:         port,
		webUIEnabled: webUIEnabled,
	}

	// Cache deployment IP at startup
	info.deploymentIP = info.detectOutboundIP()

	// Cache console URL at startup
	if webUIEnabled && info.deploymentIP != "" {
		if port == "80" {
			info.consoleURL = fmt.Sprintf("http://%s/", info.deploymentIP)
		} else {
			info.consoleURL = fmt.Sprintf("http://%s:%s/", info.deploymentIP, port)
		}
	}

	return info
}

func (a *AgentInfo) GetInfo() interface{} {
	hostname, _ := os.Hostname()

	return InfoResponse{
		Component: "bjorn2scan-agent",
		Version:   version,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func (a *AgentInfo) GetClusterName() string {
	// For agent, use hostname as cluster name
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "localhost"
	}
	return hostname
}

func (a *AgentInfo) GetDeploymentName() string {
	// For agent, deployment name is the hostname
	return a.GetClusterName()
}

func (a *AgentInfo) GetDeploymentType() string {
	return "agent"
}

func (a *AgentInfo) GetVersion() string {
	return version
}

func (a *AgentInfo) GetScanContainers() bool {
	// Agent scans containers via Docker
	return true
}

func (a *AgentInfo) GetScanNodes() bool {
	// Agent does not scan nodes
	return false
}

// detectOutboundIP determines the primary outbound IP address.
// Called once at startup and cached.
func (a *AgentInfo) detectOutboundIP() string {
	// Get primary outbound IP address by dialing a well-known address
	// This determines which local IP would be used for outbound connections
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Printf("Warning: failed to determine primary outbound IP: %v", err)
		return ""
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Warning: failed to close connection: %v", closeErr)
		}
	}()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// GetDeploymentIP returns the cached deployment IP address.
func (a *AgentInfo) GetDeploymentIP() string {
	return a.deploymentIP
}

// GetConsoleURL returns the cached console URL.
func (a *AgentInfo) GetConsoleURL() string {
	return a.consoleURL
}

// SetGrypeDBStatusGetter sets a callback function to get the grype database build timestamp.
func (a *AgentInfo) SetGrypeDBStatusGetter(getter func() string) {
	a.grypeDBStatusGetter = getter
}

// GetGrypeDBBuilt returns the grype vulnerability database build timestamp in RFC3339 format.
// Returns empty string if the database status is unavailable.
func (a *AgentInfo) GetGrypeDBBuilt() string {
	if a.grypeDBStatusGetter == nil {
		return ""
	}
	return a.grypeDBStatusGetter()
}

// registerUpdaterHandlers registers HTTP handlers for the updater
func registerUpdaterHandlers(mux *http.ServeMux, u *updater.Updater) {
	// GET /api/update/status - Get current update status
	mux.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		status, errorMsg, lastCheck, lastUpdate, latestVersion, currentVersion := u.GetStatus()
		response := map[string]interface{}{
			"status":         status,
			"error":          errorMsg,
			"lastCheck":      lastCheck,
			"lastUpdate":     lastUpdate,
			"latestVersion":  latestVersion,
			"currentVersion": currentVersion,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/trigger - Manually trigger an update check
	mux.HandleFunc("/api/update/trigger", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.TriggerCheck()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Update check triggered"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/pause - Pause automatic updates
	mux.HandleFunc("/api/update/pause", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.Pause()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Auto-updates paused"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/resume - Resume automatic updates
	mux.HandleFunc("/api/update/resume", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.Resume()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Auto-updates resumed"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})
}

// setupLogging configures logging to write to both stdout and a log file
func setupLogging() (*os.File, error) {
	logDir := "/var/log/bjorn2scan"
	logFile := filepath.Join(logDir, "agent.log")

	// Try to create log file, but don't fail if we can't
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// If we can't create the log file, just log to stdout
		log.Printf("Warning: could not open log file %s: %v (logging to stdout only)", logFile, err)
		return nil, nil
	}

	// Log to both stdout (systemd journal) and file
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags)

	return file, nil
}

func main() {
	// Setup logging to both stdout and file
	logFile, _ := setupLogging()
	if logFile != nil {
		defer func() { _ = logFile.Close() }()
	}

	// Load configuration from file with environment variable overrides
	cfg, err := config.LoadConfigWithDefaults()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	port := cfg.Port
	dbPath := cfg.DBPath

	// Initialize debug configuration
	debugConfig := debug.NewDebugConfig(cfg.DebugEnabled)
	if debugConfig.IsEnabled() {
		log.Println("Debug mode ENABLED - /debug endpoints available")
	}

	log.Printf("bjorn2scan-agent v%s starting", version)
	log.Printf("Configuration: port=%s, db_path=%s, debug=%v", port, dbPath, cfg.DebugEnabled)

	// Initialize deployment UUID
	dbDir := filepath.Dir(dbPath)
	deploymentUUID, err := deployment.NewUUID(dbDir)
	if err != nil {
		log.Fatalf("Failed to initialize deployment UUID: %v", err)
	}
	log.Printf("Deployment UUID: %s", deploymentUUID)

	// Create container manager
	manager := containers.NewManager()

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Connect database to manager
	manager.SetDatabase(db)

	// Create SBOM retriever using syft library
	// For the agent, we scan local Docker images directly
	sbomRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		// nodeName and runtime are ignored for local agent - we scan from local Docker daemon
		return syft.GenerateSBOM(ctx, image)
	}

	// Configure Grype to store vulnerability database in /var/lib/bjorn2scan/cache
	grypeCfg := grype.Config{
		DBRootDir: "/var/lib/bjorn2scan/cache",
	}

	// Create database updater for grype DB status and rescan job
	// Pass the database as TimestampStore for persistent tracking of grype DB changes
	dbUpdater, err := vulndb.NewDatabaseUpdaterWithConfig(grypeCfg.DBRootDir, vulndb.DatabaseUpdaterConfig{
		TimestampStore: db,
	})
	if err != nil {
		log.Printf("Warning: failed to create database updater: %v", err)
	}

	// Initialize grype database status at startup (for metrics)
	// This ensures grype_db_built is available in metrics immediately
	if dbUpdater != nil {
		if _, err := dbUpdater.GetCurrentStatus(context.Background()); err != nil {
			log.Printf("Warning: failed to get initial database status: %v", err)
		}
	}

	// Initialize scan queue with SBOM and vulnerability scanning
	// Using default queue config (unbounded queue with single worker)
	queueConfig := scanning.QueueConfig{
		MaxDepth:     0, // Unbounded
		FullBehavior: scanning.QueueFullDrop,
	}
	scanQueue := scanning.NewJobQueue(db, sbomRetriever, grypeCfg, queueConfig)
	defer scanQueue.Shutdown()

	// Connect scan queue to manager
	manager.SetScanQueue(scanQueue)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Check if Docker is available and start watcher
	if docker.IsDockerAvailable() {
		log.Println("Docker detected, starting container watcher")
		go func() {
			if err := docker.WatchContainers(ctx, manager); err != nil {
				log.Printf("Docker watcher error: %v", err)
			}
		}()
	} else {
		log.Println("Docker not available or not accessible, container watching disabled")
	}

	// Initialize auto-updater if enabled
	var agentUpdater *updater.Updater
	if cfg.AutoUpdateEnabled {
		log.Println("Initializing auto-updater...")
		updaterConfig := &updater.Config{
			Enabled:                cfg.AutoUpdateEnabled,
			CheckInterval:          cfg.AutoUpdateCheckInterval,
			FeedURL:                cfg.UpdateFeedURL,
			AssetBaseURL:           cfg.UpdateAssetBaseURL,
			CurrentVersion:         version,
			VerifySignatures:       cfg.UpdateVerifySignatures,
			RollbackEnabled:        cfg.UpdateRollbackEnabled,
			HealthCheckTimeout:     cfg.UpdateHealthCheckTimeout,
			CosignIdentityRegexp:   cfg.UpdateCosignIdentityRegexp,
			CosignOIDCIssuer:       cfg.UpdateCosignOIDCIssuer,
			DownloadMaxRetries:     cfg.UpdateDownloadMaxRetries,
			DownloadValidateAssets: cfg.UpdateDownloadValidateAssets,
			VersionConstraints: &updater.VersionConstraints{
				AutoUpdateMinor: cfg.AutoUpdateMinorVersions,
				AutoUpdateMajor: cfg.AutoUpdateMajorVersions,
				PinnedVersion:   cfg.AutoUpdatePinnedVersion,
				MinVersion:      cfg.AutoUpdateMinVersion,
				MaxVersion:      cfg.AutoUpdateMaxVersion,
			},
		}

		var err error
		agentUpdater, err = updater.New(updaterConfig)
		if err != nil {
			log.Printf("Warning: failed to initialize updater: %v", err)
		} else {
			// Check if there's a pending update from previous run
			// This must be done BEFORE starting the HTTP server and before starting the updater
			installer := updater.NewInstaller("", "", cfg.UpdateHealthCheckTimeout)
			if installer.ShouldCheckRollback() {
				log.Println("Pending update detected from previous run")
				// Perform health check in background after server starts
				// We can't do it now because the server isn't running yet
				go func() {
					// Wait for server to be ready
					time.Sleep(3 * time.Second)
					if err := installer.PerformPostUpdateHealthCheck(); err != nil {
						log.Printf("Post-update verification failed: %v", err)
					}
				}()
			}

			// Start updater in background
			go agentUpdater.Start()
			log.Println("Auto-updater started")
		}
	}

	// Initialize scheduler for periodic jobs
	var sched *scheduler.Scheduler
	if cfg.JobsEnabled {
		log.Println("Initializing scheduled jobs...")
		sched = scheduler.New()

		// Add rescan database job - uses grype's native update mechanism
		if cfg.JobsRescanDatabaseEnabled && dbUpdater != nil {
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
	infoProvider := NewAgentInfo(cfg.Port, cfg.WebUIEnabled)

	// Wire up grype database status getter for metrics
	// Uses GetCurrentVersion() which returns cached in-memory value (fast)
	if dbUpdater != nil {
		infoProvider.SetGrypeDBStatusGetter(func() string {
			version := dbUpdater.GetCurrentVersion()
			if version == nil || version.Built.IsZero() {
				return ""
			}
			return version.Built.Format(time.RFC3339)
		})
	}

	mux := http.NewServeMux()
	handlers.RegisterHandlers(mux, infoProvider)
	handlers.RegisterDatabaseHandlers(mux, db, nil) // Use all default handlers

	// Register static handlers only if web UI is enabled
	if cfg.WebUIEnabled {
		handlers.RegisterStaticHandlers(mux)
	}

	// Register updater API endpoints if updater is initialized
	if agentUpdater != nil {
		registerUpdaterHandlers(mux, agentUpdater)
	}

	// Register debug handlers if debug mode is enabled
	handlers.RegisterDebugHandlers(mux, db, debugConfig, scanQueue)

	// Register jobs debug handlers for listing, triggering, and viewing execution history
	handlers.RegisterJobsHandlersWithDB(mux, sched, db)

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
		log.Printf("bjorn2scan-agent listening on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, shutting down gracefully...")

	// Cancel context to stop Docker watcher
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

	log.Println("bjorn2scan-agent stopped")
}
