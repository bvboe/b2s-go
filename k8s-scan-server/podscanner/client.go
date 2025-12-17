package podscanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Client handles communication with pod-scanner instances
type Client struct {
	httpClient *http.Client
	namespace  string
}

// NewClient creates a new pod-scanner client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 6 * time.Minute, // Longer than pod-scanner's 5-minute timeout
		},
		namespace: os.Getenv("NAMESPACE"),
	}
}

// GetSBOMFromNode requests SBOM generation from pod-scanner on a specific node
// Waits for pod-scanner to become available if it's scheduled but not yet ready
func (c *Client) GetSBOMFromNode(ctx context.Context, clientset *kubernetes.Clientset, nodeName string, digest string) ([]byte, error) {
	// Try to find running pod-scanner
	pod, err := c.findPodScannerPod(ctx, clientset, nodeName)
	if err != nil {
		// Pod-scanner not running, check if we should wait
		log.Printf("Pod-scanner not immediately available on node %s: %v", nodeName, err)

		// Check if pod-scanner is scheduled (but not ready yet)
		scheduled, checkErr := c.IsPodScannerScheduledOnNode(ctx, clientset, nodeName)
		if checkErr != nil {
			return nil, fmt.Errorf("failed to check if pod-scanner is scheduled: %w", checkErr)
		}

		if scheduled {
			// Pod-scanner is scheduled, wait for it to become ready
			log.Printf("Pod-scanner is scheduled on node %s but not ready, waiting...", nodeName)
			waitErr := c.WaitForPodScannerReady(ctx, clientset, nodeName, 2*time.Minute)
			if waitErr != nil {
				return nil, fmt.Errorf("pod-scanner did not become ready: %w", waitErr)
			}

			// Try to find pod again after waiting
			pod, err = c.findPodScannerPod(ctx, clientset, nodeName)
			if err != nil {
				return nil, fmt.Errorf("failed to find pod-scanner after waiting: %w", err)
			}
		} else {
			// Not scheduled - DaemonSet won't run on this node (due to taints, node selectors, etc.)
			log.Printf("No pod-scanner scheduled on node %s, skipping (DaemonSet not scheduling to this node)", nodeName)
			return nil, fmt.Errorf("no pod-scanner scheduled on node %s (DaemonSet not configured to run on this node)", nodeName)
		}
	}

	// Build URL to pod-scanner
	url := fmt.Sprintf("http://%s:8080/sbom/%s", pod.Status.PodIP, digest)
	log.Printf("Requesting SBOM from pod-scanner: %s (node=%s)", url, nodeName)

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Send request to pod-scanner
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request SBOM from pod-scanner: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Warning: failed to close response body: %v", closeErr)
		}
	}()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pod-scanner returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read SBOM data
	sbomData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM response: %w", err)
	}

	log.Printf("Successfully received SBOM from pod-scanner (node=%s, size=%d bytes)", nodeName, len(sbomData))
	return sbomData, nil
}

// findPodScannerPod finds the pod-scanner pod running on a specific node
func (c *Client) findPodScannerPod(ctx context.Context, clientset *kubernetes.Clientset, nodeName string) (*corev1.Pod, error) {
	namespace := c.namespace
	if namespace == "" {
		namespace = "default" // Fallback to default if NAMESPACE env var not set
	}

	// List all pod-scanner pods
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=pod-scanner",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Find pod running on target node
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName == nodeName && pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return pod, nil
		}
	}

	return nil, fmt.Errorf("no running pod-scanner found on node %s", nodeName)
}

// IsPodScannerScheduledOnNode checks if a pod-scanner is scheduled (but not yet running) on a node
func (c *Client) IsPodScannerScheduledOnNode(ctx context.Context, clientset *kubernetes.Clientset, nodeName string) (bool, error) {
	namespace := c.namespace
	if namespace == "" {
		namespace = "default"
	}

	// List all pod-scanner pods
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=pod-scanner",
	})
	if err != nil {
		return false, fmt.Errorf("failed to list pods: %w", err)
	}

	// Check if any pod-scanner is scheduled or starting on this node
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName == nodeName {
			// Pod is scheduled on this node
			// Check if it's in a transitional state (Pending, ContainerCreating, etc.)
			if pod.Status.Phase == corev1.PodPending ||
			   (pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP == "") {
				return true, nil
			}
		}
	}

	return false, nil
}

// WaitForPodScannerReady waits for a pod-scanner to become ready on a node
// Returns error if timeout is reached
func (c *Client) WaitForPodScannerReady(ctx context.Context, clientset *kubernetes.Clientset, nodeName string, timeout time.Duration) error {
	log.Printf("Waiting for pod-scanner on node %s to become ready (timeout: %v)...", nodeName, timeout)

	// Wait for pod-scanner to become ready
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for pod-scanner")
		case <-ticker.C:
			// Try to find running pod-scanner
			_, err := c.findPodScannerPod(ctx, clientset, nodeName)
			if err == nil {
				log.Printf("Pod-scanner on node %s is now ready", nodeName)
				return nil
			}

			// Check if we've exceeded timeout
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for pod-scanner on node %s to become ready", nodeName)
			}
		}
	}
}
