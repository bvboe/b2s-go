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
func (c *Client) GetSBOMFromNode(ctx context.Context, clientset *kubernetes.Clientset, nodeName string, digest string) ([]byte, error) {
	// Find the pod-scanner pod running on the target node
	pod, err := c.findPodScannerPod(ctx, clientset, nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to find pod-scanner on node %s: %w", nodeName, err)
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
