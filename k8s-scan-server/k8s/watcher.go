package k8s

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// parseImageName parses a container image string into repository, tag, and imageID
// Example: "nginx:1.21" -> repository="nginx", tag="1.21"
// Example: "docker.io/library/nginx:1.21" -> repository="docker.io/library/nginx", tag="1.21"
// Example: "localhost:5000/myimage:latest" -> repository="localhost:5000/myimage", tag="latest"
func parseImageName(imageName string) (repository, tag string) {
	// Split by '@' first to handle digest
	parts := strings.Split(imageName, "@")
	imageName = parts[0]

	// Find the last ':' to separate tag (to handle registry ports like localhost:5000)
	lastColon := strings.LastIndex(imageName, ":")
	if lastColon == -1 {
		// No colon, no tag
		repository = imageName
		tag = "latest"
		return
	}

	// Check if the part after the last colon contains a slash
	// If it does, the colon is part of the registry (e.g., localhost:5000/image)
	afterColon := imageName[lastColon+1:]
	if strings.Contains(afterColon, "/") {
		// Colon is part of registry port, not a tag separator
		repository = imageName
		tag = "latest"
		return
	}

	// Normal case: colon separates repository and tag
	repository = imageName[:lastColon]
	tag = afterColon
	return
}

// extractDigestFromImageID extracts just the digest from a Kubernetes ImageID
// Example: "docker.io/library/nginx@sha256:abc123..." -> "sha256:abc123..."
// Example: "docker://sha256:abc123..." -> "sha256:abc123..."
// Example: "containerd://sha256:abc123..." -> "sha256:abc123..."
// Example: "sha256:abc123..." -> "sha256:abc123..."
func extractDigestFromImageID(imageID string) string {
	if imageID == "" {
		return ""
	}

	// Strip runtime prefix (docker://, containerd://, etc.) if present
	if idx := strings.Index(imageID, "://"); idx != -1 {
		imageID = imageID[idx+3:]
	}

	// ImageID from Kubernetes can be in format:
	// - "docker.io/library/nginx@sha256:abc123..."
	// - "sha256:abc123..."
	parts := strings.Split(imageID, "@")
	if len(parts) > 1 {
		return parts[1] // Return the digest after @
	}
	// If no @ symbol, check if it's already a digest
	if strings.HasPrefix(imageID, "sha256:") {
		return imageID
	}
	// Otherwise, return empty - this means we don't have a proper digest
	return ""
}

// extractContainerInstances extracts all container instances from a pod
func extractContainerInstances(pod *corev1.Pod) []containers.ContainerInstance {
	var instances []containers.ContainerInstance

	// Get node name from pod spec
	nodeName := pod.Spec.NodeName

	// Process all containers (init, regular, and ephemeral)
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	// Get container statuses to find imageIDs and runtimes
	type containerStatus struct {
		imageID string
		runtime string
	}
	statusMap := make(map[string]containerStatus)

	// Extract runtime from containerID (e.g., "docker://abc123" or "containerd://abc123")
	extractRuntime := func(containerID string) string {
		if strings.HasPrefix(containerID, "docker://") {
			return "docker"
		} else if strings.HasPrefix(containerID, "containerd://") {
			return "containerd"
		} else if strings.HasPrefix(containerID, "cri-o://") {
			return "cri-o"
		}
		return "unknown"
	}

	for _, status := range pod.Status.ContainerStatuses {
		statusMap[status.Name] = containerStatus{
			imageID: status.ImageID,
			runtime: extractRuntime(status.ContainerID),
		}
	}
	for _, status := range pod.Status.InitContainerStatuses {
		statusMap[status.Name] = containerStatus{
			imageID: status.ImageID,
			runtime: extractRuntime(status.ContainerID),
		}
	}

	for _, container := range allContainers {
		repository, tag := parseImageName(container.Image)
		status := statusMap[container.Name]
		// Extract just the digest part (e.g., "sha256:abc123...")
		digest := extractDigestFromImageID(status.imageID)

		// Validate that we have complete data before including this instance
		if digest == "" {
			// Skip containers without digest - they're not fully initialized yet
			// The watcher will pick them up again when status becomes available
			log.Printf("Skipping container without digest: namespace=%s, pod=%s, container=%s, image=%s",
				pod.Namespace, pod.Name, container.Name, container.Image)
			continue
		}

		if repository == "" {
			log.Printf("Warning: container has empty repository: namespace=%s, pod=%s, container=%s",
				pod.Namespace, pod.Name, container.Name)
			continue
		}

		instance := containers.ContainerInstance{
			ID: containers.ContainerInstanceID{
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Container: container.Name,
			},
			Image: containers.ImageID{
				Repository: repository,
				Tag:        tag,
				Digest:     digest,
			},
			NodeName:         nodeName,
			ContainerRuntime: status.runtime,
		}
		instances = append(instances, instance)
	}

	return instances
}

// WatchPods watches for pod changes using a SharedIndexInformer and updates the container manager.
// This implementation provides:
// - Automatic watch resumption with resourceVersion tracking (no missed events on reconnect)
// - Periodic resync to ensure eventual consistency (every 5 minutes)
// - Built-in exponential backoff on errors
// - Local cache to reduce API server load
// - Proper deletion handling even if watch connection drops
func WatchPods(ctx context.Context, clientset kubernetes.Interface, manager *containers.Manager) {
	// Create informer factory with 5-minute resync period
	// Resync ensures we eventually catch up even if watch events are missed
	resyncPeriod := 5 * time.Minute
	factory := informers.NewSharedInformerFactory(clientset, resyncPeriod)

	// Get the pod informer
	podInformer := factory.Core().V1().Pods().Informer()

	// Add event handlers
	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Printf("Unexpected object type in AddFunc: %T", obj)
				return
			}
			handlePodAddOrUpdate(pod, manager)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Printf("Unexpected object type in UpdateFunc: %T", newObj)
				return
			}
			handlePodAddOrUpdate(pod, manager)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// Handle tombstone (object deleted from cache but we got notification late)
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Printf("Unexpected object type in DeleteFunc: %T", obj)
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					log.Printf("Tombstone contained unexpected object: %T", tombstone.Obj)
					return
				}
			}
			handlePodDelete(pod, manager)
		},
	})
	if err != nil {
		log.Printf("Error adding event handler: %v", err)
		return
	}

	log.Println("Starting pod informer...")

	// Start the informer (runs in background goroutine)
	go factory.Start(ctx.Done())

	// Wait for cache to sync before considering the informer ready
	log.Println("Waiting for pod informer cache to sync...")
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		log.Println("Failed to sync pod informer cache")
		return
	}

	log.Println("Pod informer cache synced and ready")

	// Block until context is cancelled
	<-ctx.Done()
	log.Println("Pod watcher shutting down")
}

// handlePodAddOrUpdate processes pod additions and updates
func handlePodAddOrUpdate(pod *corev1.Pod, manager *containers.Manager) {
	// Only process running pods
	if pod.Status.Phase == corev1.PodRunning {
		instances := extractContainerInstances(pod)
		for _, instance := range instances {
			manager.AddContainerInstance(instance)
		}
	} else {
		// If pod is no longer running, remove its containers
		instances := extractContainerInstances(pod)
		for _, instance := range instances {
			manager.RemoveContainerInstance(instance.ID)
		}
	}
}

// handlePodDelete processes pod deletions
func handlePodDelete(pod *corev1.Pod, manager *containers.Manager) {
	// Remove all containers from this deleted pod
	instances := extractContainerInstances(pod)
	for _, instance := range instances {
		manager.RemoveContainerInstance(instance.ID)
	}
	log.Printf("Removed containers from deleted pod: namespace=%s, pod=%s", pod.Namespace, pod.Name)
}

// SyncInitialPods performs an initial sync of all existing pods.
// Note: With the informer-based WatchPods implementation, this function is less critical
// since the informer automatically performs an initial list and sync (via cache.WaitForCacheSync).
// This function is kept for explicit synchronization use cases or testing.
func SyncInitialPods(ctx context.Context, clientset kubernetes.Interface, manager *containers.Manager) error {
	log.Println("Performing initial pod sync...")

	podList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var allInstances []containers.ContainerInstance
	for _, pod := range podList.Items {
		// Only track containers from running pods
		if pod.Status.Phase == corev1.PodRunning {
			instances := extractContainerInstances(&pod)
			allInstances = append(allInstances, instances...)
		}
	}

	manager.SetContainerInstances(allInstances)
	log.Printf("Initial sync complete: %d container instances", manager.GetInstanceCount())

	return nil
}
