package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/bjorn2scan-agent/docker"
	"github.com/bvboe/b2s-go/bjorn2scan-agent/syft"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
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

type AgentInfo struct{}

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

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	log.Printf("bjorn2scan-agent v%s starting", version)

	// Create container manager
	manager := containers.NewManager()

	// Initialize database
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/bjorn2scan/containers.db"
	}
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

	// Configure Grype to store vulnerability database in /var/lib/bjorn2scan
	grypeCfg := grype.Config{
		DBRootDir: "/var/lib/bjorn2scan",
	}

	// Initialize scan queue with SBOM and vulnerability scanning
	scanQueue := scanning.NewJobQueue(db, sbomRetriever, grypeCfg)
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

	// Setup HTTP server
	infoProvider := &AgentInfo{}
	mux := http.NewServeMux()
	handlers.RegisterHandlers(mux, infoProvider)
	handlers.RegisterDatabaseHandlers(mux, db)
	handlers.RegisterStaticHandlers(mux)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
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

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("bjorn2scan-agent stopped")
}
