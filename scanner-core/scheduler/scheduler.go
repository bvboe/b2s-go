package scheduler

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// randInt63n returns a random int64 in [0, n)
// This is used for jitter calculations
func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return rand.Int63n(n)
}

// scheduledJob tracks a job and its schedule
type scheduledJob struct {
	job      Job
	schedule Schedule
	config   JobConfig
	nextRun  time.Time
	timer    *time.Timer
}

// Scheduler manages and executes scheduled jobs
type Scheduler struct {
	jobs   map[string]*scheduledJob
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new Scheduler
func New() *Scheduler {
	return &Scheduler{
		jobs: make(map[string]*scheduledJob),
	}
}

// AddJob registers a job with the scheduler
func (s *Scheduler) AddJob(job Job, schedule Schedule, config JobConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := job.Name()
	if _, exists := s.jobs[name]; exists {
		return fmt.Errorf("job %s already registered", name)
	}

	if !config.Enabled {
		log.Printf("[scheduler] Job %s is disabled, skipping", name)
		return nil
	}

	s.jobs[name] = &scheduledJob{
		job:      job,
		schedule: schedule,
		config:   config,
		nextRun:  schedule.Next(time.Now()),
	}

	log.Printf("[scheduler] Registered job: %s, next run: %s", name, s.jobs[name].nextRun.Format(time.RFC3339))
	return nil
}

// Start begins executing all scheduled jobs
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return fmt.Errorf("scheduler already started")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	// Start each job's timer
	s.mu.RLock()
	for name, sj := range s.jobs {
		log.Printf("[scheduler] Starting job: %s", name)
		s.scheduleJob(name, sj)
	}
	s.mu.RUnlock()

	log.Printf("[scheduler] Started with %d jobs", len(s.jobs))
	return nil
}

// scheduleJob sets up the timer for the next execution
func (s *Scheduler) scheduleJob(name string, sj *scheduledJob) {
	duration := time.Until(sj.nextRun)
	if duration < 0 {
		duration = 0
	}

	sj.timer = time.AfterFunc(duration, func() {
		s.executeJob(name, sj)
	})
}

// executeJob runs a job and schedules the next execution
func (s *Scheduler) executeJob(name string, sj *scheduledJob) {
	// Check if scheduler is still running
	s.mu.RLock()
	if s.ctx.Err() != nil {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	s.wg.Add(1)
	defer s.wg.Done()

	// Create context with timeout if configured
	ctx := s.ctx
	if sj.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(s.ctx, sj.config.Timeout)
		defer cancel()
	}

	// Execute the job
	start := time.Now()
	log.Printf("[scheduler] Executing job: %s", name)

	err := sj.job.Run(ctx)
	duration := time.Since(start)

	if err != nil {
		log.Printf("[scheduler] Job %s failed after %v: %v", name, duration, err)
	} else {
		log.Printf("[scheduler] Job %s completed successfully in %v", name, duration)
	}

	// Schedule next run
	s.mu.Lock()
	sj.nextRun = sj.schedule.Next(time.Now())
	log.Printf("[scheduler] Job %s next run: %s", name, sj.nextRun.Format(time.RFC3339))
	s.scheduleJob(name, sj)
	s.mu.Unlock()
}

// Stop gracefully stops the scheduler
// It waits for running jobs to complete (with a timeout)
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if s.ctx == nil {
		s.mu.Unlock()
		return fmt.Errorf("scheduler not started")
	}

	log.Printf("[scheduler] Stopping scheduler...")

	// Cancel context to signal all jobs to stop
	s.cancel()

	// Stop all timers
	for name, sj := range s.jobs {
		if sj.timer != nil {
			sj.timer.Stop()
			log.Printf("[scheduler] Stopped timer for job: %s", name)
		}
	}
	s.mu.Unlock()

	// Wait for running jobs to complete (with timeout)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[scheduler] All jobs stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Printf("[scheduler] Timeout waiting for jobs to stop")
	}

	return nil
}

// RunJobNow manually triggers a job execution (non-blocking)
func (s *Scheduler) RunJobNow(name string) error {
	s.mu.RLock()
	sj, exists := s.jobs[name]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("job %s not found", name)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ctx := s.ctx
		if sj.config.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(s.ctx, sj.config.Timeout)
			defer cancel()
		}

		log.Printf("[scheduler] Manually executing job: %s", name)
		start := time.Now()
		err := sj.job.Run(ctx)
		duration := time.Since(start)

		if err != nil {
			log.Printf("[scheduler] Manual execution of job %s failed after %v: %v", name, duration, err)
		} else {
			log.Printf("[scheduler] Manual execution of job %s completed successfully in %v", name, duration)
		}
	}()

	return nil
}

// GetJobs returns the names of all registered jobs
func (s *Scheduler) GetJobs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.jobs))
	for name := range s.jobs {
		names = append(names, name)
	}
	return names
}

// GetNextRun returns the next scheduled run time for a job
func (s *Scheduler) GetNextRun(name string) (time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sj, exists := s.jobs[name]
	if !exists {
		return time.Time{}, fmt.Errorf("job %s not found", name)
	}

	return sj.nextRun, nil
}
