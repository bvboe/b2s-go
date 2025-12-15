package k8s

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// parseImageName parses a container image string into repository, tag, and imageID
// Example: "nginx:1.21" -> repository="nginx", tag="1.21"
// Example: "docker.io/library/nginx:1.21" -> repository="docker.io/library/nginx", tag="1.21"
func parseImageName(imageName string) (repository, tag string) {
	// Split by '@' first to handle digest
	parts := strings.Split(imageName, "@")
	imageName = parts[0]

	// Split by ':' to separate tag
	parts = strings.Split(imageName, ":")
	repository = parts[0]
	if len(parts) > 1 {
		tag = parts[1]
	} else {
		tag = "latest"
	}
	return
}

// extractContainerInstances extracts all container instances from a pod
func extractContainerInstances(pod *corev1.Pod) []containers.ContainerInstance {
	var instances []containers.ContainerInstance

	// Process all containers (init, regular, and ephemeral)
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	// Get container statuses to find imageIDs
	statusMap := make(map[string]string)
	for _, status := range pod.Status.ContainerStatuses {
		statusMap[status.Name] = status.ImageID
	}
	for _, status := range pod.Status.InitContainerStatuses {
		statusMap[status.Name] = status.ImageID
	}

	for _, container := range allContainers {
		repository, tag := parseImageName(container.Image)
		imageID := statusMap[container.Name]

		instance := containers.ContainerInstance{
			ID: containers.ContainerInstanceID{
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Container: container.Name,
			},
			Image: containers.ImageID{
				Repository: repository,
				Tag:        tag,
				Digest:     imageID,
			},
		}
		instances = append(instances, instance)
	}

	return instances
}

// WatchPods watches for pod changes and updates the container manager
func WatchPods(ctx context.Context, clientset *kubernetes.Clientset, manager *containers.Manager) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Pod watcher shutting down")
			return
		default:
			watcher, err := clientset.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{})
			if err != nil {
				log.Printf("Error creating pod watcher: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			log.Println("Pod watcher started")

			for event := range watcher.ResultChan() {
				pod, ok := event.Object.(*corev1.Pod)
				if !ok {
					continue
				}

				switch event.Type {
				case watch.Added, watch.Modified:
					// Only process running pods or pods with container statuses
					if pod.Status.Phase == corev1.PodRunning || len(pod.Status.ContainerStatuses) > 0 {
						instances := extractContainerInstances(pod)
						for _, instance := range instances {
							manager.AddContainerInstance(instance)
						}
					}

				case watch.Deleted:
					// Remove all containers from this pod
					instances := extractContainerInstances(pod)
					for _, instance := range instances {
						manager.RemoveContainerInstance(instance.ID)
					}
				}
			}

			log.Println("Pod watcher connection closed, reconnecting...")
			time.Sleep(1 * time.Second)
		}
	}
}

// SyncInitialPods performs an initial sync of all existing pods
func SyncInitialPods(ctx context.Context, clientset *kubernetes.Clientset, manager *containers.Manager) error {
	log.Println("Performing initial pod sync...")

	podList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var allInstances []containers.ContainerInstance
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning || len(pod.Status.ContainerStatuses) > 0 {
			instances := extractContainerInstances(&pod)
			allInstances = append(allInstances, instances...)
		}
	}

	manager.SetContainerInstances(allInstances)
	log.Printf("Initial sync complete: %d container instances", manager.GetInstanceCount())

	return nil
}
