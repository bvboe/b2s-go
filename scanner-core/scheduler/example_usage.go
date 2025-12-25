package scheduler

// This file demonstrates how to set up and use the scheduler
// It's not meant to be executed directly, but shows the intended usage pattern

/*
Example usage in main.go or setup function:

func setupScheduler(config Config, refreshTrigger containers.RefreshTrigger) *scheduler.Scheduler {
	s := scheduler.New()

	// Job 1: Refresh images every 6 hours (periodic reconciliation)
	// This ensures the database stays in sync with running workloads
	if config.Jobs.RefreshImages.Enabled {
		refreshJob := jobs.NewRefreshImagesJob(refreshTrigger)
		s.AddJob(
			refreshJob,
			scheduler.NewIntervalSchedule(6*time.Hour),
			scheduler.JobConfig{
				Enabled: true,
				Timeout: 10*time.Minute, // Allow time for large clusters
			},
		)
	}

	// Job 2: Check for database updates every hour
	if config.Jobs.RescanDatabase.Enabled {
		rescanJob := jobs.NewRescanDatabaseJob()
		s.AddJob(
			rescanJob,
			scheduler.NewIntervalSchedule(1*time.Hour),
			scheduler.JobConfig{
				Enabled: true,
				Timeout: 30*time.Minute,
			},
		)
	}

	// Job 3: Cleanup orphaned images daily
	// Removes container_images with no associated container_instances
	// Also cleans up related packages and vulnerabilities
	if config.Jobs.Cleanup.Enabled {
		cleanupJob := jobs.NewCleanupOrphanedImagesJob(db)
		s.AddJob(
			cleanupJob,
			scheduler.NewIntervalSchedule(24*time.Hour),
			scheduler.JobConfig{
				Enabled: true,
				Timeout: 1*time.Hour,
			},
		)
	}

	// Job 4: Send telemetry every 5 minutes with 2-minute jitter
	// This prevents all instances from sending data at the same time
	if config.Jobs.Telemetry.Enabled {
		telemetryJob := jobs.NewTelemetryJob()
		s.AddJob(
			telemetryJob,
			scheduler.NewIntervalScheduleWithJitter(5*time.Minute, 2*time.Minute),
			scheduler.JobConfig{
				Enabled: true,
				Timeout: 30*time.Second,
			},
		)
	}

	return s
}

func main() {
	// Create scheduler
	s := setupScheduler(config)

	// Start scheduler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Start(ctx); err != nil {
		log.Fatalf("Failed to start scheduler: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down scheduler...")
	if err := s.Stop(); err != nil {
		log.Printf("Error stopping scheduler: %v", err)
	}
}

// Example of manually triggering a job (e.g., from HTTP endpoint)
func handleManualTrigger(s *scheduler.Scheduler, jobName string) {
	if err := s.RunJobNow(jobName); err != nil {
		log.Printf("Failed to trigger job %s: %v", jobName, err)
	}
}
*/
