package updater

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	defaultBinaryPath = "/var/lib/bjorn2scan/bin/bjorn2scan-agent"
	backupSuffix      = ".backup"
	rollbackMarker    = "/tmp/bjorn2scan-update-rollback"
)

// Installer handles atomic binary replacement and service restart
type Installer struct {
	binaryPath    string
	healthURL     string
	healthTimeout time.Duration
}

// NewInstaller creates a new installer
func NewInstaller(binaryPath, healthURL string, healthTimeout time.Duration) *Installer {
	if binaryPath == "" {
		binaryPath = defaultBinaryPath
	}
	if healthURL == "" {
		healthURL = "http://localhost:9999/health"
	}
	if healthTimeout == 0 {
		healthTimeout = 60 * time.Second
	}

	return &Installer{
		binaryPath:    binaryPath,
		healthURL:     healthURL,
		healthTimeout: healthTimeout,
	}
}

// Install performs atomic binary replacement and restarts the service
func (i *Installer) Install(newBinaryPath string) error {
	fmt.Println("Starting installation...")

	// 1. Backup current binary
	backupPath := i.binaryPath + backupSuffix
	fmt.Printf("Backing up current binary to %s...\n", backupPath)
	if err := i.copyFile(i.binaryPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup binary: %w", err)
	}

	// 2. Create rollback marker
	if err := os.WriteFile(rollbackMarker, []byte("rollback"), 0644); err != nil {
		return fmt.Errorf("failed to create rollback marker: %w", err)
	}

	// 3. Atomic replace (rename is atomic on most filesystems)
	fmt.Printf("Installing new binary to %s...\n", i.binaryPath)
	// First copy to a temp location in the same directory (ensures same filesystem)
	tempPath := i.binaryPath + ".new"
	if err := i.copyFile(newBinaryPath, tempPath); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(tempPath, 0755); err != nil {
		_ = os.Remove(tempPath) // Best effort cleanup
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, i.binaryPath); err != nil {
		_ = os.Remove(tempPath) // Best effort cleanup
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	fmt.Println("Binary installed successfully ✓")

	// 4. Restart service
	fmt.Println("Restarting service...")
	if err := i.restartService(); err != nil {
		// Try to rollback
		fmt.Printf("Service restart failed: %v\n", err)
		if rbErr := i.Rollback(); rbErr != nil {
			return fmt.Errorf("restart failed and rollback failed: %v (original error: %w)", rbErr, err)
		}
		return fmt.Errorf("service restart failed, rolled back to previous version: %w", err)
	}

	// 5. Wait for service to start and perform health check
	fmt.Printf("Waiting for service to start (timeout: %v)...\n", i.healthTimeout)
	time.Sleep(5 * time.Second) // Give service time to start

	if err := i.checkHealth(); err != nil {
		fmt.Printf("Health check failed: %v\n", err)
		if rbErr := i.Rollback(); rbErr != nil {
			return fmt.Errorf("health check failed and rollback failed: %v (original error: %w)", rbErr, err)
		}
		return fmt.Errorf("health check failed, rolled back to previous version: %w", err)
	}

	fmt.Println("Health check passed ✓")

	// 6. Remove rollback marker and backup
	_ = os.Remove(rollbackMarker) // Best effort cleanup
	_ = os.Remove(backupPath)     // Best effort cleanup

	fmt.Println("Installation completed successfully!")
	return nil
}

// Rollback restores the previous binary and restarts the service
func (i *Installer) Rollback() error {
	fmt.Println("Performing rollback...")

	backupPath := i.binaryPath + backupSuffix
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Restore backup
	if err := os.Rename(backupPath, i.binaryPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// Restart service
	if err := i.restartService(); err != nil {
		return fmt.Errorf("failed to restart service after rollback: %w", err)
	}

	// Remove rollback marker
	_ = os.Remove(rollbackMarker) // Best effort cleanup

	fmt.Println("Rollback completed")
	return nil
}

// restartService restarts the bjorn2scan-agent service
func (i *Installer) restartService() error {
	cmd := exec.Command("systemctl", "restart", "bjorn2scan-agent")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl restart failed: %w", err)
	}
	return nil
}

// checkHealth performs a health check on the service
func (i *Installer) checkHealth() error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	deadline := time.Now().Add(i.healthTimeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(i.healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}

		// Wait before retry
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("health check timeout after %v", i.healthTimeout)
}

// copyFile copies a file from src to dst
func (i *Installer) copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.WriteFile(dst, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write destination: %w", err)
	}

	return nil
}

// ShouldCheckRollback checks if there's a pending rollback check
func (i *Installer) ShouldCheckRollback() bool {
	_, err := os.Stat(rollbackMarker)
	return err == nil
}

// CleanupRollbackMarker removes the rollback marker
func (i *Installer) CleanupRollbackMarker() error {
	return os.Remove(rollbackMarker)
}

// GetBackupPath returns the path to the backup binary
func (i *Installer) GetBackupPath() string {
	return filepath.Join(filepath.Dir(i.binaryPath), filepath.Base(i.binaryPath)+backupSuffix)
}
